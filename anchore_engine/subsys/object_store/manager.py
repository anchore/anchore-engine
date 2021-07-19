import hashlib
import json
import urllib.parse
import zlib

from anchore_engine import utils
from anchore_engine.db import db_archivemetadata, session_scope
from anchore_engine.subsys import logger, object_store
from anchore_engine.subsys.object_store.config import (
    COMPRESSION_ENABLED_KEY,
    COMPRESSION_LEVEL,
    COMPRESSION_MIN_SIZE_KEY,
    COMPRESSION_SECTION_KEY,
    DEFAULT_OBJECT_STORE_MANAGER_ID,
    DRIVER_NAME_KEY,
    DRIVER_SECTION_KEY,
    extract_config,
    normalize_config,
    validate_config,
)
from anchore_engine.subsys.object_store.drivers import ObjectStorageDriver

manager_singleton = {}


class ObjectStorageManager(object):
    """
    A top-level manager for the archive system. Has a primary client based on config.

    Takes an 'archive' section configuration as input, including the driver and compression settings.

    """

    def __init__(self, config):
        """
        :param config: The entire catalog service configuration (services->catalog).
        """

        logger.debug("Initializing archive manager with config: {}".format(config))
        self.config = config
        self.archive_clients = {}

        try:
            driver = object_store.init_driver(self.config[DRIVER_SECTION_KEY])
            self.archive_clients[driver.__uri_scheme__] = driver
            self.primary_client = driver

            logger.info("Object store clients: {}".format(self.archive_clients.keys()))
            if not self.archive_clients:
                raise Exception(
                    "Archive driver set in config.yaml ({}) is not a valid driver. Valid drivers are: {}".format(
                        str(self.config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY]),
                        str(list(ObjectStorageDriver.registry.keys())),
                    )
                )

        except Exception as err:
            raise err

    def _do_compress(self, data):
        """
        Handle data compression based on global config. Returns the data to use as payload, compressed as necessary
        based on config.

        :param data:
        :return:
        """
        if (
            self.config[COMPRESSION_SECTION_KEY][COMPRESSION_ENABLED_KEY] is True
            and self.primary_client.__supports_compressed_data__
            and len(data)
            > self.config[COMPRESSION_SECTION_KEY][COMPRESSION_MIN_SIZE_KEY] * 1024
        ):
            is_compressed = True
            final_payload = utils.ensure_bytes(
                zlib.compress(utils.ensure_bytes(data), COMPRESSION_LEVEL)
            )
        else:
            is_compressed = False
            final_payload = utils.ensure_bytes(data)

        return final_payload, is_compressed

    def _do_decompress(self, is_compressed, data):
        if is_compressed:
            return zlib.decompress(data)
        else:
            return data

    def check_drivers(self):
        """
        Iterates over metadata for all documents in the system and returns the list of found driver schemas annotated with if the manager is configured to support them
        :return: list of tuples of (<supported_driver_names>, <unsupported_driver_names>)
        """
        with session_scope() as session:
            schemas = db_archivemetadata.list_schemas(session)

        my_schemas = [x.__uri_scheme__ for x in list(self.archive_clients.values())]
        my_schemas.append(self.primary_client.__uri_scheme__)
        my_schemas = set(my_schemas)
        supported = schemas.intersection(my_schemas)
        unsupported = schemas.difference(my_schemas)
        return supported, unsupported

    def get_document(self, userId: str, bucket: str, archiveId: str):
        """
        Retrieve the content of the document json-decoded.

        :param userId:
        :param bucket:
        :param archiveId:
        :return: json parsed content (e.g. object), or None if not found
        """
        if not self.archive_clients:
            raise Exception("archive not initialized")

        archive_document = self.get(userId, bucket, archiveId)
        if archive_document is not None:
            return json.loads(utils.ensure_str(archive_document)).get("document")
        else:
            return None

    def put_document(self, userId, bucket, archiveId, data):
        """
        Write a json document to the object store

        :param userId:
        :param bucket:
        :param archiveId:
        :param data: a json serializable object (string, dict, list, etc)
        :return: digest of the content stored as a string
        """
        payload = json.dumps({"document": data})

        return self.put(userId, bucket, archiveId, utils.ensure_bytes(payload))

    def get_document_meta(self, userId, bucket, archiveId):
        """
        Return the metadata for the doc, or None if not found

        :param userId:
        :param bucket:
        :param archiveId:
        :return:
        """
        if not self.archive_clients:
            raise Exception("archive not initialized")

        with session_scope() as dbsession:
            ret = db_archivemetadata.get(userId, bucket, archiveId, session=dbsession)
            if ret is None:
                return None
            else:
                return ret

    def exists(self, userId, bucket, archiveId):
        """
        Check existence of record for archive object

        :param userId:
        :param bucket:
        :param archiveId:
        :param verify_on_backend:
        :return:
        """
        with session_scope() as db:
            return db_archivemetadata.exists(userId, bucket, archiveId, session=db)

    def put(self, userId, bucket, archiveid, data):
        """
        Expects a json parsed payload to write

        :param userId:
        :param bucket:
        :param archiveid:
        :param data: string data to write
        :return: digest of the stored content
        """
        if not self.primary_client:
            raise Exception("archive not initialized")

        try:
            final_payload, is_compressed = self._do_compress(data)

            size = len(final_payload)
            digest = hashlib.md5(final_payload).hexdigest()

            url = self.primary_client.put(userId, bucket, archiveid, final_payload)
            with session_scope() as dbsession:
                db_archivemetadata.add(
                    userId,
                    bucket,
                    archiveid,
                    archiveid + ".json",
                    url,
                    is_compressed=is_compressed,
                    content_digest=digest,
                    size=size,
                    session=dbsession,
                )
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err

        return digest

    def get(self, userId, bucket, archiveid):
        if not self.archive_clients:
            raise Exception("archive not initialized")

        try:
            with session_scope() as dbsession:
                result = db_archivemetadata.get(
                    userId, bucket, archiveid, session=dbsession
                )
                if not result:
                    return None

            url = result.get("content_url")
            if url is None:
                raise Exception(
                    "Null reference url for valid metadata record for {}/{}/{}".format(
                        userId, bucket, archiveid
                    )
                )
            else:

                is_compressed = result.get("is_compressed", False)
                expected = result.get("digest")

                # get the raw data from driver, note content is bytes (not str)
                content = self._client_for(url).get_by_uri(url)
                found_size = len(content)

                if expected:
                    found = hashlib.md5(content).hexdigest()
                else:
                    found = None

                if expected and found != expected:
                    logger.error(
                        "Digest mismatch:\nDB Record: {}\nContent digest: {}\n, Content size: {}".format(
                            result, found, found_size, content
                        )
                    )
                    raise Exception(
                        "Detected digest mismatch on content fetch from backend. Expected: {}, Got: {}".format(
                            expected, found
                        )
                    )

                content = self._do_decompress(is_compressed, content)

            return content

        except Exception as err:
            import traceback

            traceback.print_exc()
            logger.debug("cannot get data: exception - " + str(err))
            raise err

    def delete_document(self, userId, bucket, archiveid):
        """
        synonym for delete()

        :param userId:
        :param bucket:2c53a13c-1765-11e8-82ef-23527761d060
        :param archiveid:
        :return:
        """
        return self.delete(userId, bucket, archiveid)

    def delete(self, userId, bucket, archiveid):
        if not self.archive_clients:
            raise Exception("archive not initialized")

        try:
            url = None
            with session_scope() as dbsession:
                meta = db_archivemetadata.get(
                    userId, bucket, archiveid, session=dbsession
                )
                if meta:
                    url = meta.get("content_url")
                    db_archivemetadata.delete(
                        userId, bucket, archiveid, session=dbsession
                    )

            # Remove the data itself. Can result in orphaned data if system fails here but better than deleting the content but not the meta, leaving a confused state.
            if url:
                scheme = urllib.parse.urlparse(url).scheme
                if scheme in self.archive_clients:
                    return self.archive_clients[scheme].delete(
                        userId, bucket, archiveid
                    )
                else:
                    logger.warn(
                        "Deleting archive document {}/{}/{}, but found no content url for backend delete so skipping backend operation".format(
                            userId, bucket, archiveid
                        )
                    )
            return url is not None

        except Exception as err:
            raise err

    def _client_for(self, content_uri: str) -> ObjectStorageDriver:
        """
        Return the configured client for the given uri, if one exists. If not found, raises a KeyError exception
        :param content_uri: str uri of content to fetch
        :return: configured ObjectStorage driver if available, else raise exception
        """

        parsed = urllib.parse.urlparse(content_uri)
        return self.archive_clients[parsed.scheme]


def get_manager(manager_id=DEFAULT_OBJECT_STORE_MANAGER_ID) -> ObjectStorageManager:
    mgr = manager_singleton.get(manager_id)
    if mgr is None:
        raise Exception(
            "Archive {} not initialized. Must call initialize() first".format(
                manager_id
            )
        )
    return mgr


def initialize(
    service_config,
    force=False,
    check_db=False,
    manager_id=None,
    config_keys=None,
    allow_legacy_fallback=False,
):
    """
    Initialize a global object storeage manager for service usage using the given id for lookup (manager_id)

    This is not thread-safe, so should be called during single-threaded service bootstrap/init. It should not
    be in the hot-path for any request execution.

    This function does some convenience config handling, for a direct initialization with prepared object storage configuration, use initialize_direct()

    :param service_config: catalog service configuration from which to extract the archive configuration
    :param force: re-initialize even if already initialized
    :param check_db: evaluate the existing db to see if drivers are present to support the data in the db
    :param manager_id: the id for the manager to initializez, will be the id to use in the get_manager() call to get this manager
    :param config_keys: tuple of keys in precedence order to search for in the service_config dict to find the config for the manager
    :param allow_legacy_fallback: boolean toggle to support very old (pre 0.2.4) object store configuration formats
    :return: true if initialized a new manager, false if already present and no-op
    """

    global manager_singleton

    if manager_singleton.get(manager_id) is not None and not force:
        # Already initialized, no-op
        return False

    obj_store_config = extract_config(service_config, config_keys=config_keys)
    archive_config = normalize_config(
        obj_store_config,
        legacy_fallback=allow_legacy_fallback,
        service_config=service_config,
    )

    return initialize_direct(archive_config, manager_id=manager_id, check_db=check_db)


def initialize_direct(obj_store_config, manager_id, check_db=False):
    """
    Given a fully-prepared configuration, initialize the manager and set the id.

    :param obj_store_config: dict, fully ready configuration to use
    :param manager_id:
    :param check_db:
    :return:
    """
    global manager_singleton

    validate_config(obj_store_config)

    manager_singleton[manager_id] = ObjectStorageManager(obj_store_config)

    if check_db:
        supported, unsupported = manager_singleton.check_drivers()
        if unsupported:
            raise Exception(
                "Archive subsys initialization found records in the metadata db that require drivers not configured: {}".format(
                    unsupported
                )
            )

    logger.info("Archive {} initialization complete".format(manager_id))
    return True


def get_driver_list():
    """
    Return the names of the registered object storage drivers

    :return: list of strings from driver names
    """
    return list(ObjectStorageDriver.registry.keys())
