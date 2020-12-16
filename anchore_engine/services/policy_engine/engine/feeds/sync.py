"""
Feeds manager system. Handles syncing and storing feed data locally for use by the policy engine.

Overall approach is to handle each feed individually with specific mapping code for the data types of each feed.
The reason for this is a more efficient (for query) data schema to support quick policy evaluations that require feed
data. Additionally, any new feed will require new code to be able to consume it in the policy eval system anyway, so
an update to the feed handling code is ok to be required as well.

"""
import os
import time
import uuid

from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import (
    get_thread_scoped_session as get_session,
    FeedMetadata,
    FeedGroupMetadata,
)
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    build_feed_sync_results,
    build_group_sync_result,
    feed_instance_by_name,
    notify_event,
    VulnerabilityFeed,
    VulnDBFeed,
    PackagesFeed,
    NvdV2Feed,
)
from anchore_engine.services.policy_engine.engine.feeds.client import get_client
from anchore_engine.services.policy_engine.engine.feeds.download import (
    FeedDownloader,
    DownloadOperationConfiguration,
    LocalFeedDataRepo,
)
from anchore_engine.services.policy_engine.engine.feeds.db import (
    get_all_feeds,
    get_all_feeds_detached,
)
from anchore_engine.subsys.events import (
    FeedSyncStarted,
    FeedSyncFailed,
    FeedSyncCompleted,
    FeedGroupSyncStarted,
    FeedGroupSyncCompleted,
    FeedGroupSyncFailed,
)
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.common.schemas import (
    GroupDownloadOperationParams,
    GroupDownloadOperationConfiguration,
    DownloadOperationConfiguration,
)


def download_operation_config_factory(
    source_uri, db_groups_to_sync, is_full_download=False
):
    """
    Create new operation configuration from the set of db entities

    :param source_uri:
    :param db_groups_to_sync: list of FeedGroupMetadata objects from the db
    :param is_full_download:
    :return:
    """
    conf = DownloadOperationConfiguration(
        uuid=uuid.uuid4().hex, source_uri=source_uri, groups=[]
    )

    for g in db_groups_to_sync:
        if not isinstance(g, FeedGroupMetadata):
            raise TypeError(
                "db_groups_to_sync must be list of FeedGroupMetadata objects"
            )

        group_download_conf = GroupDownloadOperationConfiguration()
        group_download_conf.feed = g.feed_name
        group_download_conf.group = g.name
        group_since = g.last_sync if not is_full_download else None
        group_download_conf.parameters = GroupDownloadOperationParams(since=group_since)
        conf.groups.append(group_download_conf)

    return conf


def get_feeds_config(full_config):
    """
    Returns the feeds-specifc portion of the global config. To centralized this logic.
    :param full_config:
    :return: dict that is the feeds configuration
    """
    c = full_config.get("feeds", {}) if full_config else {}
    return c if c is not None else {}


def get_selected_feeds_to_sync(config):
    """
    Given a configuration dict, determine which feeds should be synced.

    :param config: dict that is the system configuration
    :return: list of strings of feed names to sync
    """

    feed_config = get_feeds_config(config)
    select_sync_cfg = feed_config.get("selective_sync", {})
    if select_sync_cfg and select_sync_cfg.get("enabled", False):
        return [
            x[0]
            for x in [
                x
                for x in list(
                    feed_config.get("selective_sync", {}).get("feeds", {}).items()
                )
                if x[1]
            ]
        ]
    else:
        # Selective disabled... sync only 'vulnerabilities' and 'nvdv2' per semantics in previous version
        return [VulnerabilityFeed.__feed_name__, NvdV2Feed.__feed_name__]


class DataFeeds(object):
    _proxy = None

    __scratch_dir__ = None  # Override location for the downloads to write

    @classmethod
    def instance(cls):
        if not cls._proxy:
            cls._proxy = DataFeeds()
        return cls._proxy

    @staticmethod
    def update_counts():
        for feed in get_all_feeds_detached():
            try:
                f = feed_instance_by_name(feed.name)
                f.update_counts()
            except KeyError:
                logger.warn(
                    "Could not find feed instance for name %s. Cannot update counts",
                    feed.name,
                )

    @staticmethod
    def _pivot_and_filter_feeds_by_config(
        to_sync: list, source_found: list, db_found: list
    ):
        """

        :param to_sync: list of feed names requested to be synced
        :param source_found: list of feed names available as returned by the upstream source
        :param db_found: list of db records that were updated as result of upstream metadata sync (this is to handle db update failures)
        :return:
        """
        available = set(to_sync).intersection(set(source_found))
        return {x.name: x for x in db_found if x.name in available}

    @staticmethod
    def sync_metadata(
        feed_client: IFeedSource, to_sync: list = None, operation_id=None
    ) -> tuple:
        """
        Get metadata from source and sync db metadata records to that (e.g. add any new groups or feeds)
        Executes as a unit-of-work for db, so will commit result and returns the records found on upstream source.

        If a record exists in db but was not found upstream, it is not returned

        :param feed_client:
        :param to_sync: list of string feed names to sync metadata on
        :return: tuple, first element: dict of names mapped to db records post-sync only including records successfully updated by upstream, second element is a list of tuples where each tuple is (failed_feed_name, error_obj)
        """

        if not to_sync:
            return {}, []

        db = get_session()
        try:
            logger.info(
                "Syncing feed and group metadata from upstream source (operation_id={})".format(
                    operation_id
                )
            )

            source_resp = feed_client.list_feeds()
            if to_sync:
                feeds = filter(lambda x: x.name in to_sync, source_resp.feeds)
            else:
                feeds = []

            failed = []
            source_feeds = {
                x.name: {
                    "meta": x,
                    "groups": feed_client.list_feed_groups(x.name).groups,
                }
                for x in feeds
            }
            logger.debug("Upstream feeds available: %s", source_feeds)
            db_feeds = DataFeeds._pivot_and_filter_feeds_by_config(
                to_sync, list(source_feeds.keys()), get_all_feeds(db)
            )

            for feed_name, feed_api_record in source_feeds.items():
                try:
                    logger.info(
                        "Syncing metadata for feed: {} (operation_id={})".format(
                            feed_name, operation_id
                        )
                    )

                    api_feed = feed_api_record["meta"]
                    db_feed = db_feeds.get(api_feed.name)

                    # Do this instead of a db.merge() to ensure no timestamps are reset or overwritten
                    if not db_feed:
                        logger.debug(
                            "Adding new feed metadata record to db: {} (operation_id={})".format(
                                api_feed.name, operation_id
                            )
                        )
                        db_feed = FeedMetadata(
                            name=api_feed.name,
                            description=api_feed.description,
                            access_tier=api_feed.access_tier,
                            enabled=True,
                        )
                        db.add(db_feed)
                        db.flush()
                    else:
                        logger.debug(
                            "Feed metadata already in db: {} (operation_id={})".format(
                                api_feed.name, operation_id
                            )
                        )

                    # Check for any update
                    db_feed.description = api_feed.description
                    db_feed.access_tier = api_feed.access_tier

                    db_groups = {x.name: x for x in db_feed.groups}
                    for api_group in feed_api_record.get("groups", []):
                        db_group = db_groups.get(api_group.name)
                        # Do this instead of a db.merge() to ensure no timestamps are reset or overwritten
                        if not db_group:
                            logger.debug(
                                "Adding new feed metadata record to db: {} (operation_id={})".format(
                                    api_group.name, operation_id
                                )
                            )
                            db_group = FeedGroupMetadata(
                                name=api_group.name,
                                description=api_group.description,
                                access_tier=api_group.access_tier,
                                feed=db_feed,
                                enabled=True,
                            )
                            db_group.last_sync = None
                            db.add(db_group)
                        else:
                            logger.debug(
                                "Feed group metadata already in db: {} (operation_id={})".format(
                                    api_group.name, operation_id
                                )
                            )

                        db_group.access_tier = api_group.access_tier
                        db_group.description = api_group.description
                except Exception as e:
                    logger.exception("Error syncing feed {}".format(feed_name))
                    logger.warn(
                        "Could not sync metadata for feed: {} (operation_id={})".format(
                            feed_name, operation_id
                        )
                    )
                    failed.append((feed_name, e))
                finally:
                    db.flush()

            # Reload
            db_feeds = DataFeeds._pivot_and_filter_feeds_by_config(
                to_sync, list(source_feeds.keys()), get_all_feeds(db)
            )

            db.commit()
            logger.info(
                "Metadata sync from feeds upstream source complete (operation_id={})".format(
                    operation_id
                )
            )
            return db_feeds, failed
        except Exception as e:
            logger.error(
                "Rolling back feed metadata update due to error: {} (operation_id={})".format(
                    e, operation_id
                )
            )
            db.rollback()
            raise

    @staticmethod
    def sync_from_fetched(
        fetched_repo: LocalFeedDataRepo,
        catalog_client: CatalogClient = None,
        operation_id=None,
        full_flush=False,
    ):
        """
        Sync the data from a local fetched repo

        :param operation_id:
        :param catalog_client:
        :param fetched_repo:
        :return:
        """
        # Load the feed objects
        if not (
            fetched_repo.metadata
            and fetched_repo.metadata.download_result
            and fetched_repo.metadata.download_result.results
        ):
            raise ValueError("Fetched repo has no download result records")
        else:
            feed_objs = [
                feed_instance_by_name(f)
                for f in set(
                    [x.feed for x in fetched_repo.metadata.download_result.results]
                )
            ]

        result = []

        for f in feed_objs:
            try:
                t = time.time()
                try:
                    logger.info(
                        "Syncing downloaded feed data into database (operation_id={})".format(
                            operation_id
                        )
                    )
                    # Do the sync from the local data
                    result.append(
                        f.sync(
                            fetched_data=fetched_repo,
                            event_client=catalog_client,
                            operation_id=operation_id,
                            full_flush=full_flush,
                        )
                    )
                except Exception as e:
                    logger.exception(
                        "Failure updating the {} feed from downloaded data (operation_id={})".format(
                            f.__feed_name__, operation_id
                        )
                    )
                    fail_result = build_feed_sync_results(feed=f.__feed_name__)
                    fail_result["total_time_seconds"] = time.time() - t
                    result.append(fail_result)
            except:
                logger.exception(
                    "Error syncing feed {} (operation_id={})".format(
                        f.__feed_name__, operation_id
                    )
                )
                raise

        return result

    @staticmethod
    def _process_failed_feeds(failed_tuples, catalog_client, operation_id=None) -> list:
        """
        :param failed_tuples: iterable of tuples of form (str, exception or str) where element 0 is feed name and element 1 is the failure error
        :param catalog_client:
        :param operation_id:
        :return:
        """
        fail_results = []
        for name, error in failed_tuples:
            try:
                # Emit the events for a start/stop that failed since without metadata sync we cannot sync the feed reliably
                notify_event(
                    FeedSyncStarted(feed=name),
                    catalog_client,
                    operation_id=operation_id,
                )
                notify_event(
                    FeedSyncFailed(feed=name, error=error),
                    catalog_client,
                    operation_id=operation_id,
                )
            except:
                logger.exception("Error emitting feed sync failure events")
            finally:
                feed_result = build_feed_sync_results(feed=name, status="failure")
                fail_results.append(feed_result)

        return fail_results

    @staticmethod
    def sync(
        to_sync=None,
        full_flush=False,
        catalog_client=None,
        feed_client=None,
        operation_id=None,
    ):
        """
        Sync all feeds.
        :return:
        """

        result = []

        if not feed_client:
            feed_client = get_client()

        logger.info(
            "Performing sync of feeds: {} (operation_id={})".format(
                "all" if to_sync is None else to_sync, operation_id
            )
        )

        updated, failed = DataFeeds.sync_metadata(
            feed_client=feed_client, to_sync=to_sync, operation_id=operation_id
        )
        updated_names = set(updated.keys())

        # Feeds configured to sync but that were not on the upstream source at all
        for feed_name in set(to_sync).difference(updated_names):
            failed.append((feed_name, "Feed not found on upstream source"))

        # Build the list of feed instances to execute the syncs on
        feeds_to_sync = []
        for feed_name in updated_names:
            try:
                feeds_to_sync.append(feed_instance_by_name(feed_name))
            except KeyError as e:
                logger.error(
                    "Could not initialize metadata for feed {}. Error: No feed implementation found for feed {}. (operation_id={})".format(
                        feed_name, str(e), operation_id
                    )
                )
                failed.append((feed_name, e))
            except Exception as e:
                logger.error(
                    "Could not initialize metadata for feed {}. Error: {}. (operation_id={})".format(
                        feed_name, str(e), operation_id
                    )
                )
                logger.warn(
                    "Cannot sync metadata for feed {} from upstream source. Skipping. (operation_id={})".format(
                        feed_name, operation_id
                    )
                )
                failed.append((feed_name, e))

        # Process the feeds that failed for any reason pre-data-download
        result.extend(
            DataFeeds._process_failed_feeds(
                failed_tuples=failed,
                catalog_client=catalog_client,
                operation_id=operation_id,
            )
        )

        # Sort the feed instances for the syncing process to ensure highest priority feeds sync first (e.g. vulnerabilities before package metadatas)
        feeds_to_sync = _ordered_feeds(feeds_to_sync)

        # Do the fetches
        groups_to_download = []
        for f in feeds_to_sync:
            logger.info(
                "Initialized feed to sync: {} (operation_id={})".format(
                    f.__feed_name__, operation_id
                )
            )
            if f.metadata:
                if f.metadata.enabled:
                    for g in f.metadata.groups:
                        if g.enabled:
                            groups_to_download.append(g)
                        else:
                            logger.info(
                                "Will not sync/download group {} of feed {} because group is explicitly disabled".format(
                                    g.name, g.feed_name
                                )
                            )
                else:
                    logger.info(
                        "Skipping feed {} because it is explicitly not enabled".format(
                            f.__feed_name__
                        )
                    )
            else:
                logger.warn(
                    "No metadata found for feed {}. Unexpected but not an error (operation_id={})".format(
                        f.__feed_name__, operation_id
                    )
                )

        logger.debug("Groups to download {}".format(groups_to_download))

        if not feed_client:
            feed_client = get_client()

        base_dir = (
            DataFeeds.__scratch_dir__
            if DataFeeds.__scratch_dir__
            else localconfig.get_config().get("tmp_dir")
        )
        download_dir = os.path.join(base_dir, "policy_engine_tmp", "feed_syncs")

        feed_data_repo = None
        try:
            # Order by feed
            for f in feeds_to_sync:
                feed_result = build_feed_sync_results(
                    feed=f.__feed_name__, status="failure"
                )
                feed_result["status"] = "success"

                try:
                    # Feed level notification and log msg
                    notify_event(
                        FeedSyncStarted(feed=f.__feed_name__),
                        catalog_client,
                        operation_id=operation_id,
                    )

                    groups_to_sync = [
                        x for x in groups_to_download if x.feed_name == f.__feed_name__
                    ]
                    logger.debug("Groups to sync {}".format(groups_to_sync))

                    # Filter groups by that feed
                    for g in groups_to_sync:

                        # Down load just one group into a download result
                        group_download_config = download_operation_config_factory(
                            feed_client.feed_url, db_groups_to_sync=[g]
                        )
                        downloader = FeedDownloader(
                            download_root_dir=download_dir,
                            config=group_download_config,
                            client=feed_client,
                            fetch_all=full_flush,
                        )

                        logger.debug(
                            "Groups to download {}".format(downloader.config.groups)
                        )
                        try:
                            notify_event(
                                FeedGroupSyncStarted(feed=g.feed_name, group=g.name),
                                catalog_client,
                                operation_id=operation_id,
                            )

                            logger.info(
                                "Beginning feed data fetch (feed={}, group={}, operation_id={})".format(
                                    g.feed_name, g.name, operation_id
                                )
                            )
                            feed_data_repo = downloader.execute(
                                feed_name=g.feed_name, group_name=g.name
                            )

                            logger.info(
                                "Download complete. Syncing to db (feed={}, group={}, operation_id={})".format(
                                    g.feed_name, g.name, operation_id
                                )
                            )
                            f_result = DataFeeds.sync_from_fetched(
                                feed_data_repo,
                                catalog_client=catalog_client,
                                operation_id=operation_id,
                                full_flush=full_flush,
                            )

                            # Extract the single group record...
                            group_result = _get_group_result(f_result)

                            logger.info(
                                "DB Sync complete (feed={}, group={}, operation_id={})".format(
                                    g.feed_name, g.name, operation_id
                                )
                            )

                            if group_result["status"] == "success":
                                notify_event(
                                    FeedGroupSyncCompleted(
                                        feed=f.__feed_name__,
                                        group=g.name,
                                        result=group_result,
                                    ),
                                    catalog_client,
                                    operation_id=operation_id,
                                )
                            else:
                                # If any fails, the whole feed is marked as failed
                                feed_result["status"] = "failure"
                                notify_event(
                                    FeedGroupSyncFailed(
                                        feed=f.__feed_name__,
                                        group=g.name,
                                        error="Failed to sync to db",
                                    ),
                                    catalog_client,
                                    operation_id=operation_id,
                                )

                            feed_result["groups"].append(group_result)

                        except Exception as e:
                            logger.error(
                                "Error syncing {}/{} (operation_id={})".format(
                                    g.feed_name, g.name, operation_id
                                )
                            )
                            notify_event(
                                FeedGroupSyncFailed(
                                    feed=g.feed_name, group=g.name, error=e
                                ),
                                catalog_client,
                                operation_id,
                            )
                            feed_result["status"] = "failure"
                        finally:
                            try:
                                feed_data_repo.teardown()
                            except:
                                logger.exception(
                                    "Could not cleanup download repo due to error"
                                )

                            feed_data_repo = None

                except Exception as e:
                    logger.error(
                        "Error syncing {} (operation_id={})".format(f, operation_id)
                    )

                if feed_result["status"] == "success":
                    notify_event(
                        FeedSyncCompleted(feed=f.__feed_name__),
                        catalog_client,
                        operation_id,
                    )
                else:
                    notify_event(
                        FeedSyncFailed(
                            feed=f.__feed_name__,
                            error="One or more groups failed to sync",
                        ),
                        catalog_client,
                        operation_id,
                    )

                result.append(feed_result)
        finally:
            if feed_data_repo:
                feed_data_repo.teardown()

        return result

    @staticmethod
    def delete_feed_group(feed_name, group_name):
        """

        :param feed_name:
        :param group_name:
        :return:
        """

        f = feed_instance_by_name(feed_name)
        if not f:
            raise KeyError(feed_name)

        return f.flush_group(group_name)

    @staticmethod
    def delete_feed(feed_name):
        """

        :param feed_name:
        :return:
        """
        f = feed_instance_by_name(feed_name)
        if not f:
            raise KeyError(feed_name)

        return f.flush_all()


def _get_group_result(feed_result: list) -> dict:
    if not feed_result:
        raise ValueError("Invalid result list")

    groups = feed_result[0].get("groups", [])
    if groups:
        return groups[0]
    else:
        raise ValueError("No groups in result set. Expected 1")


def _ordered_feeds(feeds: list):
    return sorted(feeds, key=lambda x: _sync_order(x.__feed_name__))


def _sync_order(feed_name: str) -> int:
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
