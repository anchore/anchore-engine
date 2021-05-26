from abc import ABC, abstractmethod

from anchore_engine.db import FeedGroupMetadata
from anchore_engine.services.policy_engine.engine.feeds.client import (
    get_feeds_client,
    get_grype_db_client,
)
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.subsys import logger

GRYPE_DB_FEED_NAME = "grypedb"


class SyncUtilProvider(ABC):
    def __init__(self, sync_configs):
        self._sync_configs = self._get_filtered_sync_configs(sync_configs)
        self._to_sync = self._get_feeds_to_sync()

    @property
    def to_sync(self):
        return self._to_sync

    def _get_feeds_to_sync(self):
        return list(self._sync_configs.keys())

    @staticmethod
    @abstractmethod
    def _get_filtered_sync_configs(sync_configs):
        ...

    @abstractmethod
    def get_client(self):
        ...

    @abstractmethod
    def sync_metadata(self, source_feeds, operation_id):
        ...

    @staticmethod
    def get_groups_to_download(source_feeds, updated, feeds_to_sync, operation_id):
        ...


class LegacySyncUtilProvider(SyncUtilProvider):
    @staticmethod
    def _get_filtered_sync_configs(sync_configs):
        return {
            feed_name: sync_config
            for feed_name, sync_config in sync_configs.items()
            if feed_name != GRYPE_DB_FEED_NAME
        }

    def get_client(self):
        sync_config = list(self._sync_configs.values())[0]
        return get_feeds_client(sync_config)

    def sync_metadata(self, source_feeds, operation_id):
        return DataFeeds.sync_metadata(source_feeds, self.to_sync, operation_id)

    def get_groups_to_download(
        self, source_feeds, updated, feeds_to_sync, operation_id
    ):
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
    @staticmethod
    def _get_filtered_sync_configs(sync_configs):
        grype_sync_config = sync_configs.get(GRYPE_DB_FEED_NAME)
        if grype_sync_config:
            return {GRYPE_DB_FEED_NAME: grype_sync_config}
        return {}

    def get_client(self):
        grype_db_sync_config = self._sync_configs.get(GRYPE_DB_FEED_NAME)
        return get_grype_db_client(grype_db_sync_config)

    def sync_metadata(self, source_feeds, operation_id):
        return DataFeeds.sync_metadata(
            source_feeds, self.to_sync, operation_id, groups=False
        )

    def get_groups_to_download(
        self, source_feeds, updated, feeds_to_sync, operation_id
    ):
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
