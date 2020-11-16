"""
Entry-point for the archive subsystem, which leverages the object store subsystem. This provides a configuration and lookup
point.

This is primarily used for the analysis archive feature of the system, but is not specific to that usage.

"""
from anchore_engine.subsys.object_store.manager import initialize_direct
from anchore_engine.subsys import object_store
from anchore_engine.subsys.object_store.config import (
    ANALYSIS_ARCHIVE_MANAGER_ID,
    DEFAULT_OBJECT_STORE_MANAGER_ID,
    default_config as DEFAULT_OBJ_STORE_CONFIG,
    DRIVER_SECTION_KEY,
    DRIVER_NAME_KEY,
    extract_config as obj_store_extract_config,
)
from anchore_engine.subsys import logger

DEFAULT_BUCKET_PREFIX = "anchore_analysis_archive"

_manager_singleton = None

# The default analysis archive config is the db2 driver, for rdbms to support
DEFAULT_ANALYSIS_ARCHIVE_CONFIG = DEFAULT_OBJ_STORE_CONFIG
DEFAULT_OBJ_STORE_CONFIG[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = "db"


def extract_config(service_config, default=None):
    """
    Return an analysis archive config from the service config

    :param service_config: dict, the configuration to try to pull the analysis-archive from
    :param default: dict, the default config to use if not found
    :return: dict, the configuration found in the service config or default if not found
    """

    archive_obj_config = obj_store_extract_config(
        service_config=service_config, config_keys=[ANALYSIS_ARCHIVE_MANAGER_ID]
    )
    if not archive_obj_config:
        return default
    else:
        return archive_obj_config


def initialize(config):
    """
    Initializes the object storage manager for the analysis archive.

    NOTE: this is not thread-safe, should be called once on service startup, not in request threads/path

    :param config:
    :return:
    """
    global _manager_singleton
    if _manager_singleton is None:
        try:
            try:
                logger.debug(
                    "Initializing the analysis-archive object store driver: {}".format(
                        config.get(DRIVER_SECTION_KEY, {}).get(DRIVER_NAME_KEY)
                    )
                )
                archive_obj_config = extract_config(config)
                if archive_obj_config:
                    # There is an archive-specific configuration
                    initialize_direct(
                        archive_obj_config, manager_id=ANALYSIS_ARCHIVE_MANAGER_ID
                    )
                    _manager_singleton = ArchiveManager(ANALYSIS_ARCHIVE_MANAGER_ID)
                else:
                    # Fall-thru to use the default object-storage configuration
                    _manager_singleton = ArchiveManager(DEFAULT_OBJECT_STORE_MANAGER_ID)

            except Exception as ex:
                logger.exception("Error initializing archive manager")
        except:
            logger.exception("Could not initialize analysis archive system")
            raise
    else:
        logger.warn("Archive manager already initialized, skipping redundant init")


class ArchiveManager(object):
    """
    Wrapper around ObjectStoreManager for bucket namespacing as well as some migration abilities and metadata.

    The bucket prefix is a logical bucket prefix for the anchore bucket. Obj storage drivers will have their own actual
    bucket used in the backing store such this logical prefix typically becomes a key prefix since bucket names are immutable from that
    set in the driver config.

    This prefix ensures that on a shared backend driver with regular object storage there aren't logical bucket name conflicts

    """

    def __init__(self, object_manager_id):
        self.obj_manager = object_store.get_manager(object_manager_id)
        logger.debug(
            "Archive manager initialized using object storage driver: {}".format(
                self.obj_manager.primary_client.__config_name__
            )
        )

    def _bucket(self, name):
        return name

    def get(self, account, bucket, archiveId) -> bytes:
        return self.obj_manager.get(account, self._bucket(bucket), archiveId)

    def get_document_meta(self, account, bucket, archiveId) -> dict:
        return self.obj_manager.get_document_meta(
            account, self._bucket(bucket), archiveId
        )

    def exists(self, account, bucket, archiveId) -> bool:
        return self.obj_manager.exists(account, self._bucket(bucket), archiveId)

    def delete(self, account, bucket, archiveId) -> bool:
        return self.obj_manager.delete(account, self._bucket(bucket), archiveId)

    def delete_document(self, account, bucket, archiveId) -> bool:
        return self.obj_manager.delete_document(
            account, self._bucket(bucket), archiveId
        )

    def put(self, account, bucket, archiveId, data) -> str:
        return self.obj_manager.put(account, self._bucket(bucket), archiveId, data)


def get_manager() -> ArchiveManager:
    """
    Returns the object storage manager for the archive subsys
    :return:
    """
    global _manager_singleton
    if _manager_singleton is None:
        raise Exception("Not initialized. Call init_archive_manager")
    return _manager_singleton
