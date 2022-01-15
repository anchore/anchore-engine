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
from dataclasses import asdict
from typing import Dict, List, Optional, Union

from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.models.schemas import (
    DownloadOperationConfiguration,
    FeedAPIGroupRecord,
    FeedAPIRecord,
    GroupDownloadOperationConfiguration,
    GroupDownloadOperationParams,
)
from anchore_engine.configuration import localconfig
from anchore_engine.db import FeedGroupMetadata
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.services.policy_engine.engine.feeds.db import get_all_feeds_detached
from anchore_engine.services.policy_engine.engine.feeds.download import (
    FeedDownloader,
    LocalFeedDataRepo,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    FeedSyncResult,
    NvdV2Feed,
    PackagesFeed,
    VulnDBFeed,
    VulnerabilityFeed,
    feed_instance_by_name,
)
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    SyncUtilProvider,
)
from anchore_engine.subsys import logger
from anchore_engine.subsys.events import (
    EventBase,
    FeedGroupSyncCompleted,
    FeedGroupSyncFailed,
    FeedGroupSyncStarted,
    FeedSyncCompleted,
    FeedSyncFailed,
    FeedSyncStarted,
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

    # @staticmethod
    # def get_grype_db_listing(
    #         feed_group_information, grypedb_feed_name
    # ) -> GrypeDBListing:
    #     for feed_name, feed_api_record in feed_group_information.items():
    #         if feed_name == grypedb_feed_name:
    #             return next(group.grype_listing for group in feed_api_record["groups"])

    @staticmethod
    def get_feed_group_information(
        feed_client: IFeedSource,
        to_sync: List[str] = None,
    ) -> Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]:
        """
        Uses API client to populate a mapping.

        :param feed_client: feed client to download from
        :type feed_client: IFeedSource
        :param to_sync: list of feed names to download
        :type to_sync: List[str]
        :return: mapping containing API response
        :rtype: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        """
        if not to_sync:
            return {}

        source_resp = feed_client.list_feeds()
        if to_sync:
            feeds = filter(lambda x: x.name in to_sync, source_resp.feeds)
        else:
            feeds = []
        source_feeds = {
            x.name: {
                "meta": x,
                "groups": feed_client.list_feed_groups(x.name).groups,
            }
            for x in feeds
        }
        logger.debug("Upstream feeds available: %s", source_feeds)
        return source_feeds

    @staticmethod
    def sync_from_fetched(
        fetched_repo: LocalFeedDataRepo,
        catalog_client: CatalogClient = None,
        operation_id=None,
        full_flush=False,
    ) -> List[FeedSyncResult]:
        """
        Sync the data from a local fetched repo

        :param operation_id:
        :param catalog_client:
        :param fetched_repo:
        :param full_flush:
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

        result: List[FeedSyncResult] = []

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
                except Exception:
                    logger.exception(
                        "Failure updating the {} feed from downloaded data (operation_id={})".format(
                            f.__feed_name__, operation_id
                        )
                    )
                    fail_result = FeedSyncResult(
                        feed=f.__feed_name__, total_time_seconds=int(time.time() - t)
                    )
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
            except Exception:
                logger.exception("Error emitting feed sync failure events")
            finally:
                feed_result = FeedSyncResult(feed=name, status="failure")
                fail_results.append(feed_result)

        return fail_results

    @staticmethod
    def sync(
        sync_util_provider: SyncUtilProvider,
        full_flush: bool = False,
        catalog_client: CatalogClient = None,
        operation_id: Optional[str] = None,
    ) -> List[FeedSyncResult]:
        """
        Sync all feeds.

        :param sync_util_provider: provider for sync utils (switches logic for legacy / grypedb feeds)
        :type sync_util_provider: SyncUtilProvider
        :param full_flush: whether not not to flush out the existing records before sync
        :type full_flush: bool
        :param catalog_client: catalog client
        :type catalog_client: CatalogClient
        :param operation_id: UUID4 hexadecimal string representing this operation
        :type operation_id: Optional[str]
        :return: list of FeedSyncResult
        :rtype: List[FeedSyncResult]
        """
        result = []
        to_sync = sync_util_provider.to_sync
        if not to_sync:
            return result
        feed_client = sync_util_provider.get_client()

        logger.info(
            "Performing sync of feeds: {} (operation_id={})".format(
                "all" if to_sync is None else to_sync, operation_id
            )
        )
        source_feeds = DataFeeds.get_feed_group_information(feed_client, to_sync)
        updated, failed = sync_util_provider.sync_metadata(source_feeds, operation_id)
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

        groups_to_download = sync_util_provider.get_groups_to_download(
            source_feeds, feeds_to_sync, operation_id
        )

        logger.debug("Groups to download {}".format(groups_to_download))

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
                feed_result = FeedSyncResult(feed=f.__feed_name__, status="success")

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
                            group_result = sync_util_provider.retrieve_group_result(
                                f_result, g
                            )

                            logger.info(
                                "DB Sync complete (feed={}, group={}, operation_id={})".format(
                                    g.feed_name, g.name, operation_id
                                )
                            )

                            if group_result.status == "success":
                                notify_event(
                                    FeedGroupSyncCompleted(
                                        feed=f.__feed_name__,
                                        group=g.name,
                                        result=asdict(group_result),
                                    ),
                                    catalog_client,
                                    operation_id=operation_id,
                                )
                            else:
                                # If any fails, the whole feed is marked as failed
                                feed_result.status = "failure"
                                notify_event(
                                    FeedGroupSyncFailed(
                                        feed=f.__feed_name__,
                                        group=g.name,
                                        error="Failed to sync to db",
                                    ),
                                    catalog_client,
                                    operation_id=operation_id,
                                )

                            sync_util_provider.update_feed_result(
                                feed_result, f_result, group_result
                            )

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
                            feed_result.status = "failure"
                        finally:
                            try:
                                feed_data_repo.teardown()
                            except Exception:
                                logger.exception(
                                    "Could not cleanup download repo due to error"
                                )

                            feed_data_repo = None

                except Exception:
                    logger.exception(
                        "Error syncing {} (operation_id={})".format(f, operation_id)
                    )

                if feed_result.status == "success":
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
        # TODO throw exception if feed is grypedb
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


def _ordered_feeds(feeds: list):
    return sorted(feeds, key=lambda x: _sync_order(x.__feed_name__))


def _sync_order(feed_name: str) -> int:
    """
    helper function to establish basic sync order. Lowest syncs first

    :param feed_name:
    :return:
    """

    # Later will want to generalize this and add sync order as property of the feed class

    if feed_name == VulnerabilityFeed.__feed_name__:
        return 1
    if feed_name == VulnDBFeed.__feed_name__:
        return 10
    if feed_name == NvdV2Feed.__feed_name__:
        return 50
    if feed_name == PackagesFeed.__feed_name__:
        return 100
    else:
        # Anything else is less than packages but more than the vuln-related
        return 99


def notify_event(event: EventBase, client: CatalogClient, operation_id=None):
    """
    Send an event or just log it if client is None
    Always log the event to info level
    """

    if client:
        try:
            client.add_event(event)
        except Exception as e:
            logger.warn("Error adding feed start event: {}".format(e))

    try:
        logger.info("Event: {} (operation_id={})".format(event.to_json(), operation_id))
    except TypeError:
        logger.exception("Error logging event")
