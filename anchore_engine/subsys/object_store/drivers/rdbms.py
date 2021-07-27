import base64
import urllib.parse

from anchore_engine import db, utils
from anchore_engine.db import db_archivedocument, db_objectstorage
from anchore_engine.subsys import logger
from anchore_engine.subsys.object_store.exc import ObjectKeyNotFoundError

from .interface import ObjectStorageDriver


class LegacyDbDriver(ObjectStorageDriver):
    """
    Store the data in an sql db table. This is kept for upgrade purposes to migrate to the plugin model overall.
    """

    __config_name__ = "db"
    __uri_scheme__ = "db"
    __supports_compressed_data__ = False  # Will do compression in the db, but must be given string content, not binary

    def __init__(self, config):
        super(LegacyDbDriver, self).__init__(config)
        self.initialized = True

    def get(self, userId: str, bucket: str, key: str) -> bytes:
        if not self.initialized:
            raise Exception("archive not initialized")

        return self.get_by_uri(self.uri_for(userId, bucket, key))

    def _parse_uri(self, uri: str) -> (str, str, str):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        userId = parsed.netloc
        empty, bucket, key = parsed.path.split("/", 2)
        return userId, bucket, key

    def get_by_uri(self, uri: str) -> bytes:
        userId, bucket, key = self._parse_uri(uri)

        try:
            with db.session_scope() as dbsession:
                result = db_archivedocument.get(userId, bucket, key, session=dbsession)
            if result:
                return utils.ensure_bytes(self._decode(result))
            else:
                raise ObjectKeyNotFoundError(userId, bucket, key, caused_by=None)
        except Exception as err:
            logger.debug("cannot get data: exception - " + str(err))
            raise err

    def put(self, userId: str, bucket: str, key: str, data: bytes) -> str:
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            with db.session_scope() as dbsession:
                str_data, is_b64 = self._encode(data)
                dbdata = {"jsondata": str_data, "b64_encoded": is_b64}

                db_archivedocument.add(
                    userId, bucket, key, key + ".json", inobj=dbdata, session=dbsession
                )
                return self.uri_for(userId, bucket, key)
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err

    def delete_by_uri(self, uri: str) -> bool:
        userId, bucket, key = self._parse_uri(uri)
        return self.delete(userId, bucket, key)

    def delete(self, userId: str, bucket: str, key: str) -> bool:
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            with db.session_scope() as dbsession:
                rc = db_archivedocument.delete(userId, bucket, key, session=dbsession)
                if not rc:
                    raise Exception("failed to delete DB record")
                else:
                    return True
        except Exception as err:
            raise err

    def uri_for(self, userId: str, bucket: str, key: str) -> str:
        return "{}://{}/{}/{}".format(self.__uri_scheme__, userId, bucket, key)

    def get_document_meta(self, userId: str, bucket: str, key: str) -> dict:
        with db.session_scope() as dbsession:
            return db_archivedocument.get_onlymeta(
                userId, bucket, key, session=dbsession
            )

    def _encode(self, data: bytes):
        try:
            str_data = str(data, "utf-8")
            is_b64 = False
        except UnicodeError:
            str_data = str(base64.encodebytes(data), "utf-8")
            is_b64 = True

        return str_data, is_b64

    def _decode(self, raw_result):
        is_b64 = bool(raw_result.get("b64_encoded", False))
        data = raw_result.get("jsondata")
        if data and is_b64:
            return base64.decodebytes(utils.ensure_bytes(data))
        elif data is None:
            return b""
        else:
            return data


class DbDriver(ObjectStorageDriver):
    """
    Store the data in an sql db table as a blob
    """

    __config_name__ = "db2"
    __uri_scheme__ = "db2"

    def __init__(self, config: dict):
        super(DbDriver, self).__init__(config)
        self.initialized = True

    def _to_key(self, userId: str, bucket: str, key: str) -> str:
        return "/".join([userId, bucket, key])

    def _parse_uri(self, uri: str) -> (str, str, str):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        userId = parsed.netloc
        bucket, key = parsed.path[1:].split("/", 1)

        return userId, bucket, key

    def get_by_uri(self, uri: str) -> bytes:
        userId, bucket, key = self._parse_uri(uri)
        return self.get(userId, bucket, key)

    def exists(self, uri: str) -> bool:
        userId, bucket, key = self._parse_uri(uri)
        with db.session_scope() as dbsession:
            return db_objectstorage.exists(userId, bucket, key, session=dbsession)

    def get(self, userId: str, bucket: str, key: str) -> bytes:
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            with db.session_scope() as dbsession:
                result = db_objectstorage.get(userId, bucket, key, session=dbsession)
                if result and "content" in result:
                    data = result.get("content")
                    # Clean return of empty
                    if data is None:
                        return b""
                    else:
                        return utils.ensure_bytes(result.get("content"))
                else:
                    raise ObjectKeyNotFoundError(userId, bucket, key, caused_by=None)
        except Exception as err:
            logger.debug("cannot get data: exception - " + str(err))
            raise err

    def put(self, userId: str, bucket: str, key: str, data: bytes) -> str:
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            d = utils.ensure_bytes(data)

            with db.session_scope() as dbsession:
                if db_objectstorage.put(userId, bucket, key, d, session=dbsession):
                    return self.uri_for(userId, bucket, key)
                else:
                    raise Exception("Db operation to save object returned failure")
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err

    def delete(self, userId: str, bucket: str, key: str) -> bool:
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            with db.session_scope() as dbsession:
                rc = db_objectstorage.delete(userId, bucket, key, session=dbsession)
                if not rc:
                    raise Exception("failed to delete DB record")
                else:
                    return True
        except Exception as err:
            raise err

    def delete_by_uri(self, uri: str) -> bool:
        userId, bucket, key = self._parse_uri(uri)
        return self.delete(userId, bucket, key)

    def uri_for(self, userId: str, bucket: str, key: str) -> str:
        return "{}://{}".format(self.__uri_scheme__, self._to_key(userId, bucket, key))
