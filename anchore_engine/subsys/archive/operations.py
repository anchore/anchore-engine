from anchore_engine.decorators import delegate_to_callable
from anchore_engine.subsys import logger
from anchore_engine.subsys import object_store
from .config import normalize_config
from .manager import ArchiveManager

manager_singleton = None


def get_archive():
    if manager_singleton is None:
        raise Exception('Archive not initialized. Must call initialize() first')
    return manager_singleton


def initialize(service_config, force=False, check_db=False):
    """
    Initialize the global archive manager for service usage.

    :param service_config: catalog service configuration from which to extract the archive configuration
    :param force: re-initialize even if already initialized
    :return:
    """

    global manager_singleton

    if manager_singleton is not None and not force:
        # Already initialized, no-op
        return

    archive_config = normalize_config(service_config)

    manager_singleton = ArchiveManager(archive_config)

    if check_db:
        supported, unsupported = manager_singleton.check_drivers()
        if unsupported:
            raise Exception('Archive subsys initialization found records in the metadata db that require drivers not configured: {}'.format(unsupported))

    logger.info('Archive initialization complete')
    return True


def get_driver_list():
    """
    Return the names of the registered object storage drivers

    :return: list of strings from driver names
    """
    return list(object_store.ObjectStorageDriver.registry.keys())


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def get_document(userId, bucket, archiveId):
    pass


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def put_document(userId, bucket, archiveId, data):
    pass


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def put(userId, bucket, archiveId, data):
    pass


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def get_document_meta(userId, bucket, archiveId):
    pass


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def exists(userId, bucket, archiveId):
    pass


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def get(userId, bucket, archiveid):
    pass


def delete_document(userId, bucket, archiveid):
    """
    synonym for delete()
    """
    return delete(userId, bucket, archiveid)


@delegate_to_callable(get_archive, 'Must call initialize() before archive operations are available')
def delete(userId, bucket, archiveid):
    pass
