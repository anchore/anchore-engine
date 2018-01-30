"""
Archive Subsystem is for storing and retrieving documents (json text specifically).
Semantics are simple CRUD using namespaced defined by userId and bucket name.

Archive documents are stored in a driver-based backend with refreneces kept in the archive_document table to determine where and how to access documents and
any state necessary (e.g. for garbage collection or time-out)
"""
import copy
import json
import zlib
import urlparse
import hashlib
from anchore_engine.db import db_archivemetadata, session_scope

from anchore_engine.subsys import logger
from anchore_engine.subsys import object_store
import anchore_engine.subsys.object_store.drivers

archive_clients = {}
DEFAULT_DRIVER = 'db'

# The configured read-write driver. There can (currently) only be one configured writeable driver
primary_client = None

COMPRESSION_LEVEL = 3

# Config Keys
DEFAULT_MIN_COMPRESSION_LIMIT_KB = 100
MAIN_CONFIG_KEY = 'archive'
COMPRESSION_SECTION_KEY = 'compression'
COMPRESSION_ENABLED_KEY = 'enabled'
COMPRESSION_MIN_SIZE_KEY = 'min_size_kbytes'
DRIVER_SECTION_KEY = 'storage_driver'
DRIVER_NAME_KEY = 'name'
DRIVER_CONFIG_KEY = 'config'
MIGRATION_DRIVER_SECTION_KEY = 'migrate_from_storage_driver'
DEFAULT_COMPRESSION_ENABLED = False


default_config = {
    COMPRESSION_SECTION_KEY: {
        COMPRESSION_ENABLED_KEY: DEFAULT_COMPRESSION_ENABLED,
        COMPRESSION_MIN_SIZE_KEY: DEFAULT_MIN_COMPRESSION_LIMIT_KB,
    },
    DRIVER_SECTION_KEY: {
        DRIVER_NAME_KEY: DEFAULT_DRIVER,
        DRIVER_CONFIG_KEY: {}
    }
}

archive_configuration = None


def client_for(content_uri):
    """
    Return the configured client for the given uri, if one exists. If not found, raises a KeyError exception
    :param content_uri: str uri of content to fetch
    :return: configured ObjectStorage driver if available, else raise exception
    """

    parsed = urlparse.urlparse(content_uri)
    return archive_clients[parsed.scheme]


def initialize(archive_config):
    """
    Initialize the archve system. If driver_config is not provide, looks for it in the broader system configuration under services->catalog->archive_driver.

    Must be called before the other methods in this module for crud operations.

    :param archive_config:
    :return: True on successful initialization
    """

    global archive_clients, primary_client, archive_configuration

    try:
        archive_configuration = copy.copy(default_config)
        if DRIVER_SECTION_KEY in archive_config:
            archive_configuration[DRIVER_SECTION_KEY].update(archive_config[DRIVER_SECTION_KEY])
        if COMPRESSION_SECTION_KEY in archive_config:
            archive_configuration[COMPRESSION_SECTION_KEY].update(archive_config[COMPRESSION_SECTION_KEY])

        validate_config(archive_configuration)

        driver = object_store.init_driver(archive_configuration[DRIVER_SECTION_KEY])
        archive_clients[driver.__uri_scheme__] = driver
        primary_client = driver

        if not archive_clients:
            raise Exception("Archive driver set in config.yaml ({}) is not a valid driver. Valid drivers are: {}".format(str(archive_configuration[DRIVER_SECTION_KEY][DRIVER_NAME_KEY]), str(object_store.ObjectStorageDriver.registry.keys())))

    except Exception as err:
        raise err

    logger.debug("archive initialization config: {}".format(archive_configuration))
    return (True)


def validate_config(config):
    """
    Validates either the config exists or is empty and thus defaults. Does not validate specific driver configs as those are up to the drivers themselves.

    :param config:
    :return:
    """
    try:
        if DRIVER_SECTION_KEY in config:
            name = config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY]
            drv_cfg = config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY]
        return True
    except Exception as e:
        raise Exception('Invalid archive driver configuration: {}'.format(e))


def _parse_legacy_config(config):
    """
    Checks a config for older versions of config values. e.g. 'use-db'.

    If no legacy config is found, returns the exact config given.

    :param config: config dict
    :return: parsed archive config values as a dict
    """
    mapped_config = {
        DRIVER_SECTION_KEY: {
            DRIVER_NAME_KEY: None,
            DRIVER_CONFIG_KEY: {}
        }
    }

    if 'archive_driver' in config and type(config['archive_driver']) in [str, unicode]:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY] = config['archive_driver']
    else:
        return config

    if 'use_db' in config and config['use_db']:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = 'db'

    if mapped_config[DRIVER_SECTION_KEY] == 'fs' and 'archive_data_dir' in config:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY]['data_dir'] = config['archive_data_dir']

    if mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] is not None:
        return mapped_config
    else:
        return config


def get_driver_list():
    """
    Return the names of the registered object storage drivers

    :return: list of strings from driver names
    """
    return object_store.ObjectStorageDriver.registry.keys()

# Document functions -- json encoded

def get_document(userId, bucket, archiveId):
    """
    Retrieve the content of the document json-decoded.

    :param userId:
    :param bucket:
    :param archiveId:
    :return: json parsed content (e.g. object)
    """
    if not archive_clients:
        raise Exception("archive not initialized")

    archive_document = get(userId, bucket, archiveId)
    return json.loads(archive_document).get('document')


def put_document(userId, bucket, archiveId, data):
    payload = json.dumps({'document': data})

    return put(userId, bucket, archiveId, payload)


def get_document_meta(userId, bucket, archiveId):
    if not archive_clients:
        raise Exception("archive not initialized")

    with session_scope() as dbsession:
        ret = db_archivemetadata.get(userId, bucket, archiveId, session=dbsession)

    return (ret)


# String functions -- no encoding

def put(userId, bucket, archiveid, data):
    """
    Expects a json parsed payload to write

    :param userId:
    :param bucket:
    :param archiveid:
    :param data: string data to write
    :return:
    """
    if not primary_client:
        raise Exception("archive not initialized")

    try:
        is_compressed = False
        final_payload = data
        digest = None

        if archive_configuration[COMPRESSION_SECTION_KEY][COMPRESSION_ENABLED_KEY] is True and primary_client.__supports_compressed_data__ and len(data) > archive_configuration[COMPRESSION_SECTION_KEY][COMPRESSION_MIN_SIZE_KEY] * 1024:
            is_compressed = True
            final_payload = zlib.compress(data, COMPRESSION_LEVEL)

        size = len(final_payload)
        digest = hashlib.md5(final_payload).hexdigest()

        url = primary_client.put(userId, bucket, archiveid, final_payload)
        with session_scope() as dbsession:
            db_archivemetadata.add(userId, bucket, archiveid, archiveid + ".json", url, is_compressed=is_compressed, content_digest=digest, size=size, session=dbsession)

    except Exception as err:
        logger.debug("cannot put data: exception - " + str(err))
        raise err

    return (True)


def get(userId, bucket, archiveid):
    if not archive_clients:
        raise Exception("archive not initialized")

    try:
        with session_scope() as dbsession:
            result = db_archivemetadata.get(userId, bucket, archiveid, session=dbsession)

        url = result.get('content_url')
        is_compressed = result.get('is_compressed', False)
        expected = result.get('digest')

        content = client_for(url).get_by_uri(url)
        found_size = len(content)

        if expected:
            found = hashlib.md5(content).hexdigest()
        else:
            found = None

        if expected and found != expected:
            logger.error('Digest mismatch:\nDB Record: {}\nContent digest: {}\n, Content size: {}'.format(result, found, found_size, content))
            raise Exception('Detected digest mismatch on content fetch from backend. Expected: {}, Got: {}'.format(expected, found))

        if is_compressed:
            content = zlib.decompress(content)

        return content

    except Exception as err:

        logger.debug("cannot get data: exception - " + str(err))
        raise err


def delete_document(userId, bucket, archiveid):
    """
    synonym for delete()

    :param userId:
    :param bucket:2c53a13c-1765-11e8-82ef-23527761d060
    :param archiveid:
    :return:
    """
    return delete(userId, bucket, archiveid)


def delete(userId, bucket, archiveid):
    if not archive_clients:
        raise Exception("archive not initialized")

    try:
        url = None
        with session_scope() as dbsession:
            meta = db_archivemetadata.get(userId, bucket, archiveid, session=dbsession)
            if meta:
                url = meta.get('content_url')
                db_archivemetadata.delete(userId, bucket, archiveid, session=dbsession)

        # Remove the data itself. Can result in orphaned data if system fails here but better than deleting the content but not the meta, leaving a confused state.
        if url:
            scheme = urlparse.urlparse(url).scheme
            if scheme in archive_clients:
                return archive_clients[scheme].delete(userId, bucket, archiveid)
            else:
                logger.warn('Deleting archive document {}/{}/{}, but found no content url for backend delete so skipping backend operation'.format(userId, bucket, archiveid))

    except Exception as err:
        raise err
