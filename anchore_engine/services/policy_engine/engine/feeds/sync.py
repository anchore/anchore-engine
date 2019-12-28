"""
Feeds manager system. Handles syncing and storing feed data locally for use by the policy engine.

Overall approach is to handle each feed individually with specific mapping code for the data types of each feed.
The reason for this is a more efficient (for query) data schema to support quick policy evaluations that require feed
data. Additionally, any new feed will require new code to be able to consume it in the policy eval system anyway, so
an update to the feed handling code is ok to be required as well.

"""
import os
import time

from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import get_thread_scoped_session as get_session, FeedMetadata, FeedGroupMetadata
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.services.policy_engine.engine.feeds.feeds import build_feed_sync_results, DataFeed, feed_instance_by_name, notify_event, VulnerabilityFeed, VulnDBFeed, PackagesFeed, NvdV2Feed
from anchore_engine.services.policy_engine.engine.feeds.client import get_client, FeedAPIRecord, FeedAPIGroupRecord
from anchore_engine.services.policy_engine.engine.feeds.download import FeedDownloader, DownloadOperationConfiguration, LocalFeedDataRepo
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.feeds.db import get_all_feeds
from anchore_engine.subsys.events import FeedSyncStarted, FeedSyncFailed, FeedSyncCompleted
from anchore_engine.configuration import localconfig

log = get_logger()


def get_feeds_config(full_config):
    """
    Returns the feeds-specifc portion of the global config. To centralized this logic.
    :param full_config:
    :return: dict that is the feeds configuration
    """
    c = full_config.get('feeds', {}) if full_config else {}
    return c if c is not None else {}


def get_selected_feeds_to_sync(config):
    """
    Given a configuration dict, determine which feeds should be synced.

    :param config: dict that is the system configuration
    :return: list of strings of feed names to sync
    """

    feed_config = get_feeds_config(config)
    select_sync_cfg = feed_config.get('selective_sync', {})
    if select_sync_cfg and select_sync_cfg.get('enabled', False):
        return [x[0] for x in [x for x in list(feed_config.get('selective_sync', {}).get('feeds', {}).items()) if x[1]]]
    else:
        # Selective disabled... sync only 'vulnerabilities' and 'nvdv2' per semantics in previous version
        return [VulnerabilityFeed.__feed_name__, NvdV2Feed.__feed_name__]


class DataFeeds(object):
    _proxy = None

    __scratch_dir__ = None # Override location for the downloads to write

    @classmethod
    def instance(cls):
        if not cls._proxy:
            cls._proxy = DataFeeds()
        return cls._proxy

    @staticmethod
    def records_for(feed_name, group_name):
        try:
            return feed_instance_by_name(feed_name).record_count(group_name)
        except KeyError as e:
            log.debug('cannot compute record count for unknown feed: {}'.format(e))
            return 0

    @staticmethod
    def _pivot_and_filter_feeds_by_config(to_sync: list, source_found: list, db_found: list):
        """

        :param to_sync: list of feed names requested to be synced
        :param source_found: list of feed names available as returned by the upstream source
        :param db_found: list of db records that were updated as result of upstream metadata sync (this is to handle db update failures)
        :return:
        """
        available = set(to_sync).intersection(set(source_found))
        return {x.name: x for x in db_found if x.name in available}

    @staticmethod
    def sync_metadata(feed_client: IFeedSource, to_sync: list = None, operation_id=None) -> dict:
        """
        Get metadata from source and sync db metadata records to that (e.g. add any new groups or feeds)
        Executes as a unit-of-work for db, so will commit result and returns the records found on upstream source.

        If a record exists in db but was not found upstream, it is not returned

        :param feed_client:
        :param to_sync: list of string feed names to sync metadata on
        :return: dict of names mapped to db records post-sync only including records successfully updated by upstream
        """

        if not to_sync:
            return {}

        db = get_session()
        try:
            log.info('Syncing feed and group metadata from upstream source (operation_id={})'.format(operation_id))

            source_resp = feed_client.list_feeds()
            if to_sync:
                feeds = filter(lambda x: x.name in to_sync, source_resp.feeds)
            else:
                feeds = []

            source_feeds = {x.name: {'meta': x, 'groups': feed_client.list_feed_groups(x.name).groups} for x in feeds}

            log.debug('Upstream feeds available: {}'.format(source_feeds))

            db_feeds = DataFeeds._pivot_and_filter_feeds_by_config(to_sync, list(source_feeds.keys()), get_all_feeds(db))

            for feed_name, feed_api_record in source_feeds.items():
                try:
                    log.info('Syncing metadata for feed: {} (operation_id={})'.format(feed_name, operation_id))

                    api_feed = feed_api_record['meta']
                    db_feed = db_feeds.get(api_feed.name)

                    # Do this instead of a db.merge() to ensure no timestamps are reset or overwritten
                    if not db_feed:
                        log.debug('Adding new feed metadata record to db: {} (operation_id={})'.format(api_feed.name, operation_id))
                        db_feed = FeedMetadata(name=api_feed.name, description=api_feed.description, access_tier=api_feed.access_tier)
                        db.add(db_feed)
                        db.flush()
                    else:
                        log.debug('Feed metadata already in db: {} (operation_id={})'.format(api_feed.name, operation_id))

                    # Check for any update
                    db_feed.description = api_feed.description
                    db_feed.access_tier = api_feed.access_tier

                    db_groups = {x.name: x for x in db_feed.groups}
                    for api_group in feed_api_record.get('groups', []):
                        db_group = db_groups.get(api_group.name)
                        # Do this instead of a db.merge() to ensure no timestamps are reset or overwritten
                        if not db_group:
                            log.debug('Adding new feed metadata record to db: {} (operation_id={})'.format(api_group.name, operation_id))
                            db_group = FeedGroupMetadata(name=api_group.name, description=api_group.description, access_tier=api_group.access_tier, feed=db_feed)
                            db_group.last_sync = None
                            db.add(db_group)
                        else:
                            log.debug('Feed group metadata already in db: {} (operation_id={})'.format(api_group.name, operation_id))

                        db_group.access_tier = api_group.access_tier
                        db_group.description = api_group.description
                except:
                    log.exception('Error syncing feed {}'.format(feed_name))
                    log.warn('Could not sync metadata for feed: {} (operation_id={})'.format(feed_name, operation_id))
                finally:
                    db.flush()

            # Reload
            db_feeds = DataFeeds._pivot_and_filter_feeds_by_config(to_sync, list(source_feeds.keys()), get_all_feeds(db))

            db.commit()
            log.info('Metadata sync from feeds upstream source complete (operation_id={})'.format(operation_id))
            return db_feeds
        except Exception as e:
            log.error('Rolling back feed metadata update due to error: {} (operation_id={})'.format(e, operation_id))
            db.rollback()
            raise

    @staticmethod
    def sync_from_fetched(fetched_repo: LocalFeedDataRepo, catalog_client: CatalogClient = None, operation_id=None):
        """
        Sync the data from a local fetched repo

        :param operation_id:
        :param catalog_client:
        :param fetched_repo:
        :return:
        """
        # Load the feed objects
        if not (fetched_repo.metadata and fetched_repo.metadata.download_result and fetched_repo.metadata.download_result.results):
            raise ValueError('Fetched repo has no download result records')
        else:
            feed_objs = [feed_instance_by_name(f) for f in set([x.feed for x in fetched_repo.metadata.download_result.results])]

        result = []
        all_success = True

        for f in feed_objs:
            try:
                t = time.time()
                notify_event(FeedSyncStarted(feed=f.__feed_name__), catalog_client)
                try:
                    log.info('Syncing downloaded feed data into database (operation_id={})'.format(operation_id))

                    # Do the sync from the local data
                    result.append(f.sync(fetched_data=fetched_repo, event_client=catalog_client))

                    if result[-1]['status'] == 'success':
                        notify_event(FeedSyncCompleted(feed=f.__feed_name__), catalog_client)
                    else:
                        notify_event(FeedSyncFailed(feed=f.__feed_name__, error=result[-1]), catalog_client)
                except Exception as e:
                    log.exception('Failure updating the {} feed from downloaded data (operation_id={})'.format(f.__feed_name__, operation_id))
                    notify_event(FeedSyncFailed(feed=f.__feed_name__, error=e), catalog_client)
                    all_success = False
                    fail_result = build_feed_sync_results()
                    fail_result['feed'] = f.__feed_name__
                    fail_result['total_time_seconds'] = time.time() - t
                    result.append(fail_result)
            except:
                log.exception('Error syncing feed {} (operation_id={})'.format(f.__feed_name__, operation_id))
                raise

        if not all_success:
            raise Exception("one or more feeds failed to sync")

        return result

    @staticmethod
    def sync(to_sync=None, full_flush=False, catalog_client=None, feed_client=None, operation_id=None):
        """
        Sync all feeds.
        :return:
        """
        all_success = True
        result = []

        if not feed_client:
            feed_client = get_client()

        log.info('Performing sync of feeds: {} (operation_id={})'.format('all' if to_sync is None else to_sync, operation_id))

        f = DataFeeds.sync_metadata(feed_client=feed_client, to_sync=to_sync, operation_id=operation_id)

        # Filter by the metadata updates we got
        meta_synced = list(f.keys())

        log.info('Successfully synced metadata for feeds: {} (operation_id={})'.format(meta_synced, operation_id))

        feeds_to_sync = []
        for f in meta_synced:
            try:
                feeds_to_sync.append(feed_instance_by_name(f))
            except Exception as e:
                log.error('Could not initialize metadata for feed {}. Error: {}. (operation_id={})'.format(f, str(e), operation_id))
                log.warn('Cannot sync metadata for feed {} from upstream source. Skipping. (operation_id={})'.format(f, operation_id))

        failed = []
        for f in failed:
            feeds_to_sync.remove(f)

        log.debug('Removed failed metadata syncs from download phase: {} (operation_id={})'.format(failed, operation_id))

        # Do the fetches
        groups_to_download = []
        for f in feeds_to_sync:
            log.info('Initialized feed to sync: {} (operation_id={})'.format(f.__feed_name__, operation_id))
            if f.metadata:
                groups_to_download.extend(f.metadata.groups)
            else:
                log.warn('No metadata found for feed {}. Unexpected but not an error (operation_id={})'.format(f.__feed_name__, operation_id))

        if not feed_client:
            feed_client = get_client()

        base_dir = DataFeeds.__scratch_dir__ if DataFeeds.__scratch_dir__ else localconfig.get_config().get('tmp_dir')
        download_dir = os.path.join(base_dir, 'policy_engine_tmp', 'feed_syncs')
        download_config = DownloadOperationConfiguration.generate_new(feed_client.feed_url, db_groups_to_sync=groups_to_download)
        downloader = FeedDownloader(download_root_dir=download_dir, config=download_config, client=feed_client, fetch_all=full_flush)
        feed_data_repo = None
        try:
            for g in sorted(download_config.groups, key=lambda x: _sync_order(x.feed, x.group)):
                try:
                    log.info('Beginning feed data fetch (feed={}, group={}, operation_id={})'.format(g.feed, g.group, operation_id))
                    feed_data_repo = downloader.execute(feed_name=g.feed, group_name=g.group)
                    log.info('Download complete. Syncing to db (feed={}, group={}, operation_id={})'.format(g.feed, g.group, operation_id))
                    result.extend(DataFeeds.sync_from_fetched(feed_data_repo, catalog_client, operation_id=operation_id))
                    log.info('Sync complete. Syncing to db (feed={}, group={}, operation_id={})'.format(g.feed, g.group, operation_id))
                except:
                    log.error('Error syncing {}/{} (operation_id={})'.format(g.feed, g.group, operation_id))
        finally:
            if feed_data_repo:
                feed_data_repo.teardown()

        if failed:
            raise Exception('one or more feeds failed to sync metadata: {}'.format([x.__feed_name__ for x in failed]))

        return result


def _sync_order(feed_name: str, group_name: str) -> int:
    """
    helper function to establish basic sync order. Lowest syncs first

    :param feed_name:
    :param group_name:
    :return:
    """

    # Later will want to generalize this and add sync order as property of the feed class

    if feed_name == VulnerabilityFeed.__feed_name__:
        return 0
    if feed_name == VulnDBFeed.__feed_name__:
        return 10
    if feed_name == NvdV2Feed.__feed_name__:
        return 50
    if feed_name == PackagesFeed.__feed_name__:
        return 100
    else:
        # Anything else is less than packages but more than the vuln-related
        return 99

