from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from anchore_engine.db import FeedGroupMetadata, FeedMetadata
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.services.policy_engine.engine.feeds.client import (
    get_feeds_client,
    get_grype_db_client,
)
from anchore_engine.services.policy_engine.engine.feeds.config import SyncConfig
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    DataFeed,
    GrypeDBFeed,
)
from anchore_engine.services.policy_engine.engine.feeds.sync import (
    DataFeeds,
    SourceFeeds,
)
from anchore_engine.subsys import logger

GRYPE_DB_FEED_NAME = GrypeDBFeed.__feed_name__


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
        self, source_feeds: SourceFeeds, operation_id: Optional[str]
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]:
        """
        Wraps DataFeeds.sync_metadata so that it may be called with arguments appropriate for the provider.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of DataFeeds.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]
        """
        ...

    @staticmethod
    def get_groups_to_download(
        source_feeds: SourceFeeds,
        updated: Dict[str, FeedMetadata],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Returns a list of FeedGroupMetadata for each feed group to download.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param updated: dict of names mapped to db records post-sync only including records successfully updated by upstream
        :type updated: Dict[str, FeedMetadata]
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

    def get_client(self) -> IFeedSource:
        """
        Instantiates the FeedServiceClient

        :return: instance of FeedServiceClient
        :rtype: IFeedSource
        """
        sync_config = list(self._sync_configs.values())[0]
        return get_feeds_client(sync_config)

    def sync_metadata(
        self, source_feeds: SourceFeeds, operation_id: Optional[str]
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]:
        """
        Wraps DataFeeds.sync_metadata so that it may be called with arguments appropriate for the provider.
        In this case, we want to make sure that syncing FeedGroupMetadata is enabled for the legacy feeds.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of DataFeeds.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]
        """
        return DataFeeds.sync_metadata(source_feeds, self.to_sync, operation_id)

    @staticmethod
    def get_groups_to_download(
        source_feeds: SourceFeeds,
        updated: Dict[str, FeedMetadata],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Iterates over feeds_to_sync, reads the FeedMetadata, and makes a list of FeedGroupMetadata objects where
        enabled == True.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param updated: dict of names mapped to db records post-sync only including records successfully updated by upstream
        :type updated: Dict[str, FeedMetadata]
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

    def get_client(self) -> IFeedSource:
        """
        Instantiates the GrypeDBServiceClient

        :return: instance of GrypeDBServiceClient
        :rtype: IFeedSource
        """
        grype_db_sync_config = self._sync_configs.get(GRYPE_DB_FEED_NAME)
        return get_grype_db_client(grype_db_sync_config)

    def sync_metadata(
        self, source_feeds: SourceFeeds, operation_id: Optional[str]
    ) -> Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]:
        """
        Wraps DataFeeds.sync_metadata so that it may be called with arguments appropriate for the provider.
        In this case, we want to make sure that syncing FeedGroupMetadata is disabled for grypedb feed.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return: response of DataFeeds.sync_metadata()
        :rtype: Tuple[Dict[str, FeedMetadata], List[Tuple[str, BaseException]]]
        """
        return DataFeeds.sync_metadata(
            source_feeds, self.to_sync, operation_id, groups=False
        )

    @staticmethod
    def get_groups_to_download(
        source_feeds: SourceFeeds,
        updated: Dict[str, FeedMetadata],
        feeds_to_sync: List[DataFeed],
        operation_id: str,
    ) -> List[FeedGroupMetadata]:
        """
        Creates a FeedGroupMetadata record that is never added to the database. We purposefully avoid adding the feed
        attribute to the record so that this record does not get created implicitly by sqlalchemy back-population.

        :param source_feeds: mapping containing FeedAPIRecord and FeedAPIGroupRecord
        :type source_feeds: SourceFeeds
        :param updated: dict of names mapped to db records post-sync only including records successfully updated by upstream
        :type updated: Dict[str, FeedMetadata]
        :param feeds_to_sync: ordered list of DataFeed(s) to sync
        :type feeds_to_sync: List[DataFeed]
        :param operation_id: UUID4 hexadecimal string
        :type operation_id: Optional[str]
        :return:
        """
        api_feed_group = source_feeds[GRYPE_DB_FEED_NAME]["groups"][0]
        feed_metadata = updated[GRYPE_DB_FEED_NAME]
        group_to_download = FeedGroupMetadata(
            name=api_feed_group.name,
            feed_name=feed_metadata.name,
            description=api_feed_group.description,
            access_tier=api_feed_group.access_tier,
            enabled=True,
        )
        return [group_to_download]
