from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy.orm.session import Session

from anchore_engine.common.schemas import FeedAPIGroupRecord, FeedAPIRecord
from anchore_engine.db import FeedGroupMetadata, FeedMetadata
from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.services.policy_engine.engine.feeds.client import (
    FeedServiceClient,
    GrypeDBServiceClient,
    get_feeds_client,
    get_grype_db_client,
)
from anchore_engine.services.policy_engine.engine.feeds.config import SyncConfig
from anchore_engine.services.policy_engine.engine.feeds.db import get_all_feeds
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    DataFeed,
    GrypeDBFeed,
)
from anchore_engine.subsys import logger

GRYPE_DB_FEED_NAME = GrypeDBFeed.__feed_name__


class MetadataSyncUtils:
    @staticmethod
    def _pivot_and_filter_feeds_by_config(
        to_sync: list, source_found: list, db_found: list
    ) -> Dict[str, FeedMetadata]:
        """
        Filters FeedMetadata records to only include those that are configured

        :param to_sync: list of feed names requested to be synced
        :param source_found: list of feed names available as returned by the upstream source
        :param db_found: list of db records that were updated as result of upstream metadata sync (this is to handle db update failures)
        :return: dict of feed names to FeedMetadata records
        :rtype: Dict[str, FeedMetadata]
        """
        available = set(to_sync).intersection(set(source_found))
        return {x.name: x for x in db_found if x.name in available}

    @staticmethod
    def _sync_feed_metadata(
        db: Session,
        feed_api_record: Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]],
        db_feeds: Dict[str, FeedMetadata],
        operation_id: Optional[str] = None,
    ) -> Dict[str, FeedMetadata]:
        """
        Add FeedMetadata records to DB if they don't already exist

        :param db: database session
        :type db: Session
        :param feed_api_record: data from API client
        :type feed_api_record: Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        :param db_feeds: map of feed names to FeedMetadata
        :type db_feeds: Dict[str, FeedMetadata]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: map of feed names to FeedMetadata that has been updated or created in the DB
        :rtype: Dict[str, FeedMetadata]
        """
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
            return {api_feed.name: db_feed}
        else:
            logger.debug(
                "Feed metadata already in db: {} (operation_id={})".format(
                    api_feed.name, operation_id
                )
            )
            return db_feeds

    @staticmethod
    def _sync_feed_group_metadata(
        db: Session,
        feed_api_record: Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]],
        db_feeds: Dict[str, FeedMetadata],
        operation_id: Optional[str] = None,
    ) -> None:
        """
        Add FeedGroupMetadata records to DB if they don't already exist

        :param db: database session
        :type db: Session
        :param feed_api_record: data from API client
        :type feed_api_record: Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        :param db_feeds: map of feed names to FeedMetadata tied to DB session
        :type db_feeds: Dict[str, FeedMetadata]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        """
        api_feed = feed_api_record["meta"]
        db_feed = db_feeds.get(api_feed.name)
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

    @staticmethod
    def sync_metadata(
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        to_sync: List[str] = None,
        operation_id: Optional[str] = None,
        groups: bool = True,
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]:
        """
        Get metadata from source and sync db metadata records to that (e.g. add any new groups or feeds)
        Executes as a unit-of-work for db, so will commit result and returns the records found on upstream source.

        If a record exists in db but was not found upstream, it is not returned

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param to_sync: list of string feed names to sync metadata on
        :type to_sync: List[str]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :param groups: whether or not to sync group metadata (defaults to True, which will sync group metadata)
        :type groups: bool
        :return: tuple, first element: dict of names mapped to db records post-sync only including records successfully updated by upstream, second element is a list of tuples where each tuple is (failed_feed_name, error_obj)
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]
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
            failed = []
            db_feeds = MetadataSyncUtils._pivot_and_filter_feeds_by_config(
                to_sync, list(source_feeds.keys()), get_all_feeds(db)
            )

            for feed_name, feed_api_record in source_feeds.items():
                try:
                    logger.info(
                        "Syncing metadata for feed: {} (operation_id={})".format(
                            feed_name, operation_id
                        )
                    )
                    feed_metadata_map = MetadataSyncUtils._sync_feed_metadata(
                        db, feed_api_record, db_feeds, operation_id
                    )
                    if groups:
                        MetadataSyncUtils._sync_feed_group_metadata(
                            db, feed_api_record, feed_metadata_map, operation_id
                        )
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
            db_feeds = MetadataSyncUtils._pivot_and_filter_feeds_by_config(
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


class SyncUtilProvider(ABC):
    """
    Base class for SyncUtilProviders.
    Encapsulates all feeds sync logic that functions differently for legacy feeds vs grypedb.

    :param sync_configs: mapping of feed names to SyncConfigs
    :type sync_configs: Dict[str, SyncConfig]
    """

    def __init__(self, sync_configs: Dict[str, SyncConfig]):
        self._sync_configs: Dict[str, SyncConfig] = self._get_filtered_sync_configs(
            sync_configs
        )
        self._to_sync: List[str] = self._get_feeds_to_sync()

    @property
    def to_sync(self) -> List[str]:
        """
        Getter for list of feeds to sync.

        :return: list of feeds to sync
        :rtype: List[str]
        """
        return self._to_sync

    def _get_feeds_to_sync(self):
        """
        Convert dict of sync configs to list of feed names that are enabled for this provider.

        :return: list of feeds to sync
        :rtype: List[str]
        """
        return list(self._sync_configs.keys())

    @staticmethod
    @abstractmethod
    def _get_filtered_sync_configs(sync_configs) -> Dict[str, SyncConfig]:
        """
        Filters sync configs to those applicable to this provider

        :param sync_configs: unfiltered mapping of feed names to SyncConfigs
        :type sync_configs: Dict[str, SyncConfig]
        :return: filtered mapping of feed names to SyncConfigs
        :rtype: Dict[str, SyncConfig]
        """
        ...

    @abstractmethod
    def get_client(self) -> IFeedSource:
        """
        Instantiate the appropriate feed client (implementation of IFeedSource) for this provider

        :return: instance of GrypeDBServiceClient or FeedServiceClient
        :rtype: IFeedSource
        """
        ...

    @abstractmethod
    def sync_metadata(
        self,
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        operation_id: Optional[str],
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]:
        """
        Wraps MetadataSyncUtils.sync_metadata so that it may be called with arguments appropriate for the provider.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of MetadataSyncUtils.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]
        """
        ...

    @staticmethod
    def get_groups_to_download(
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Returns a list of FeedGroupMetadata for each feed group to download.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param feeds_to_sync: ordered list of DataFeed(s) to sync
        :type feeds_to_sync: List[DataFeed]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return:
        """
        ...


class LegacySyncUtilProvider(SyncUtilProvider):
    """
    Encapsulates all feeds sync logic that functions differently for legacy feeds.
    """

    @staticmethod
    def _get_filtered_sync_configs(sync_configs) -> Dict[str, SyncConfig]:
        """
        Filters sync configs to those applicable to this provider.
        Filters out SyncConfig for grypedb.

        :param sync_configs: unfiltered mapping of feed names to SyncConfigs
        :type sync_configs: Dict[str, SyncConfig]
        :return: filtered mapping of feed names to SyncConfigs
        :rtype: Dict[str, SyncConfig]
        """
        return {
            feed_name: sync_config
            for feed_name, sync_config in sync_configs.items()
            if feed_name != GRYPE_DB_FEED_NAME
        }

    def get_client(self) -> FeedServiceClient:
        """
        Instantiates the FeedServiceClient

        :return: instance of FeedServiceClient
        :rtype: FeedServiceClient
        """
        sync_config = list(self._sync_configs.values())[0]
        return get_feeds_client(sync_config)

    def sync_metadata(
        self,
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        operation_id: Optional[str],
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]:
        """
        Wraps MetadataSyncUtils.sync_metadata so that it may be called with arguments appropriate for the provider.
        In this case, we want to make sure that syncing FeedGroupMetadata is enabled for the legacy feeds.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of MetadataSyncUtils.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]
        """
        return MetadataSyncUtils.sync_metadata(source_feeds, self.to_sync, operation_id)

    @staticmethod
    def get_groups_to_download(
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Iterates over feeds_to_sync, reads the FeedMetadata, and makes a list of FeedGroupMetadata objects where
        enabled == True.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param feeds_to_sync: ordered list of DataFeed(s) to sync
        :type feeds_to_sync: List[DataFeed]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return:
        """
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
        return groups_to_download


class GrypeDBSyncUtilProvider(SyncUtilProvider):
    """
    Encapsulates all feeds sync logic that functions differently for grypedb feed.
    """

    @staticmethod
    def _get_filtered_sync_configs(sync_configs) -> Dict[str, SyncConfig]:
        """
        Filters sync configs to those applicable to this provider.
        Filters out SyncConfig that are NOT grypedb.

        :param sync_configs: unfiltered mapping of feed names to SyncConfigs
        :type sync_configs: Dict[str, SyncConfig]
        :return: filtered mapping of feed names to SyncConfigs
        :rtype: Dict[str, SyncConfig]
        """
        grype_sync_config = sync_configs.get(GRYPE_DB_FEED_NAME)
        if grype_sync_config:
            return {GRYPE_DB_FEED_NAME: grype_sync_config}
        return {}

    def get_client(self) -> GrypeDBServiceClient:
        """
        Instantiates the GrypeDBServiceClient

        :return: instance of GrypeDBServiceClient
        :rtype: GrypeDBServiceClient
        """
        grype_db_sync_config = self._sync_configs.get(GRYPE_DB_FEED_NAME)
        return get_grype_db_client(grype_db_sync_config)

    def sync_metadata(
        self,
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        operation_id: Optional[str],
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]:
        """
        Wraps MetadataSyncUtils.sync_metadata so that it may be called with arguments appropriate for the provider.
        In this case, we want to make sure that syncing FeedGroupMetadata is disabled for grypedb feed.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of MetadataSyncUtils.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, Union[str, BaseException]]]]
        """
        return MetadataSyncUtils.sync_metadata(
            source_feeds, self.to_sync, operation_id, groups=False
        )

    @staticmethod
    def get_groups_to_download(
        source_feeds: Dict[
            str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]
        ],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Creates a FeedGroupMetadata record that is never added to the database. We purposefully avoid adding the feed
        attribute to the record so that this record does not get created implicitly by sqlalchemy back-population.
        Uses FeedMetadata from feeds_to_sync. Expects only one record is present for grypedb.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: Dict[str, Dict[str, Union[FeedAPIRecord, List[FeedAPIGroupRecord]]]]
        :param feeds_to_sync: ordered list of DataFeed(s) to sync
        :type feeds_to_sync: List[DataFeed]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return:
        """
        # TODO consider throwing exceptions if length is not 1 for these
        api_feed_group = source_feeds[GRYPE_DB_FEED_NAME]["groups"][0]
        feed_metadata = feeds_to_sync[0].metadata
        group_to_download = FeedGroupMetadata(
            name=api_feed_group.name,
            feed_name=feed_metadata.name,
            description=api_feed_group.description,
            access_tier=api_feed_group.access_tier,
            enabled=True,
        )
        return [group_to_download]
