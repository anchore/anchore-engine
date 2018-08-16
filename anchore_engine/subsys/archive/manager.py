import hashlib
import json
import urllib.parse
import zlib

from anchore_engine import utils
from anchore_engine.db import session_scope, db_archivemetadata
from anchore_engine.subsys import object_store, logger
from anchore_engine.subsys.archive.config import DRIVER_SECTION_KEY, DRIVER_NAME_KEY, COMPRESSION_SECTION_KEY, COMPRESSION_ENABLED_KEY, COMPRESSION_LEVEL, COMPRESSION_MIN_SIZE_KEY


class ArchiveManager(object):
    """
    A top-level manager for the archive system. Has a primary client based on config.

    Takes an 'archive' section configuration as input, including the driver and compression settings.

    """

    def __init__(self, archive_configuration):
        """
        :param archive_configuration: The entire catalog service configuration (services->catalog). 
        """

        logger.debug('Initializing archive manager with config: {}'.format(archive_configuration))
        self.config = archive_configuration
        self.archive_clients = {}

        try:
            driver = object_store.init_driver(self.config[DRIVER_SECTION_KEY])
            self.archive_clients[driver.__uri_scheme__] = driver
            self.primary_client = driver

            if not self.archive_clients:
                raise Exception("Archive driver set in config.yaml ({}) is not a valid driver. Valid drivers are: {}".format(str(self.config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY]), str(list(object_store.ObjectStorageDriver.registry.keys()))))

        except Exception as err:
            raise err

    def _do_compress(self, data):
        """
        Handle data compression based on global config. Returns the data to use as payload, compressed as necessary
        based on config.

        :param data:
        :return:
        """
        if self.config[COMPRESSION_SECTION_KEY][COMPRESSION_ENABLED_KEY] is True and self.primary_client.__supports_compressed_data__ and len(data) > \
                self.config[COMPRESSION_SECTION_KEY][COMPRESSION_MIN_SIZE_KEY] * 1024:
            is_compressed = True
            final_payload = utils.ensure_bytes(zlib.compress(utils.ensure_bytes(data), COMPRESSION_LEVEL))
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
        return (supported, unsupported)

    def get_document(self, userId, bucket, archiveId):
        """
        Retrieve the content of the document json-decoded.

        :param userId:
        :param bucket:
        :param archiveId:
        :return: json parsed content (e.g. object)
        """
        if not self.archive_clients:
            raise Exception("archive not initialized")

        archive_document = self.get(userId, bucket, archiveId)
        return json.loads(archive_document).get('document')

    def put_document(self, userId, bucket, archiveId, data):
        payload = json.dumps({'document': data})

        return self.put(userId, bucket, archiveId, payload)

    def get_document_meta(self, userId, bucket, archiveId):
        if not self.archive_clients:
            raise Exception("archive not initialized")

        with session_scope() as dbsession:
            ret = db_archivemetadata.get(userId, bucket, archiveId, session=dbsession)

        return (ret)

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
        :return:
        """
        if not self.primary_client:
            raise Exception("archive not initialized")

        try:
            final_payload, is_compressed = self._do_compress(data)

            size = len(final_payload)
            digest = hashlib.md5(final_payload).hexdigest()

            url = self.primary_client.put(userId, bucket, archiveid, final_payload)
            with session_scope() as dbsession:
                db_archivemetadata.add(userId, bucket, archiveid, archiveid + ".json", url, is_compressed=is_compressed, content_digest=digest, size=size, session=dbsession)
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err

        return True

    def get(self, userId, bucket, archiveid):
        if not self.archive_clients:
            raise Exception("archive not initialized")

        try:
            with session_scope() as dbsession:
                result = db_archivemetadata.get(userId, bucket, archiveid, session=dbsession)

            url = result.get('content_url')
            is_compressed = result.get('is_compressed', False)
            expected = result.get('digest')

            # get the raw data from driver, note content is bytes (not str)
            content = self._client_for(url).get_by_uri(url)
            found_size = len(content)

            if expected:
                found = hashlib.md5(content).hexdigest()
            else:
                found = None

            if expected and found != expected:
                logger.error('Digest mismatch:\nDB Record: {}\nContent digest: {}\n, Content size: {}'.format(result, found, found_size, content))
                raise Exception(
                    'Detected digest mismatch on content fetch from backend. Expected: {}, Got: {}'.format(expected, found))

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
                meta = db_archivemetadata.get(userId, bucket, archiveid, session=dbsession)
                if meta:
                    url = meta.get('content_url')
                    db_archivemetadata.delete(userId, bucket, archiveid, session=dbsession)

            # Remove the data itself. Can result in orphaned data if system fails here but better than deleting the content but not the meta, leaving a confused state.
            if url:
                scheme = urllib.parse.urlparse(url).scheme
                if scheme in self.archive_clients:
                    return self.archive_clients[scheme].delete(userId, bucket, archiveid)
                else:
                    logger.warn(
                        'Deleting archive document {}/{}/{}, but found no content url for backend delete so skipping backend operation'.format(
                            userId, bucket, archiveid))

        except Exception as err:
            raise err

    def _client_for(self, content_uri):
        """
        Return the configured client for the given uri, if one exists. If not found, raises a KeyError exception
        :param content_uri: str uri of content to fetch
        :return: configured ObjectStorage driver if available, else raise exception
        """

        parsed = urllib.parse.urlparse(content_uri)
        return self.archive_clients[parsed.scheme]
