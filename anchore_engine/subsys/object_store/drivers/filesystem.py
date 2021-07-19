import hashlib
import os
import re
import urllib.parse

from anchore_engine import utils
from anchore_engine.subsys import logger
from anchore_engine.subsys.object_store.exc import ObjectKeyNotFoundError

from .interface import ObjectStorageDriver


class FilesystemObjectStorageDriver(ObjectStorageDriver):
    """
    A Driver that uses a mounted filesystem on the host for storing documents. This driver does not handle distribution or replication.
    If you want to use a filesystem but want replication and redundancy across nodes, you must use a shared/distributed filesystem like Gluster, Nfs, CephFS, EFS, etc.

    """

    __config_name__ = "localfs"
    __driver_version__ = "2"
    __uri_scheme__ = "file"

    _initialized = False

    def __init__(self, config):
        """
        :param configuration_section:
        """

        super(FilesystemObjectStorageDriver, self).__init__(config)

        try:
            self.data_volume = None
            if "archive_data_dir" in self.config:
                self.data_volume = self.config["archive_data_dir"]
            else:
                raise ValueError(
                    'Configuration missing "archive_data_dir" key to indicate where to store data'
                )

            self.initialized = self._initialize_archive_file()

        except Exception as err:
            raise err

        logger.debug("archive initialization config: {}".format(self.config))

    def _initialize_archive_file(self):
        try:
            if not os.path.exists(self.data_volume):
                os.makedirs(self.data_volume)

            # quick check to make sure the volume looks like a legitimate archive layout
            unknowns = []
            for fname in os.listdir(self.data_volume):
                fpath = os.path.join(self.data_volume, fname)
                if not os.path.isdir(fpath) or not re.match("[0-9A-Fa-f]{32}", fname):
                    unknowns.append(fname)
            if unknowns:
                raise Exception(
                    "found unknown files in archive data volume ("
                    + str(self.data_volume)
                    + ") - data_volume must be set to a directory used only for anchore-engine archive documents: unknown files found: "
                    + str(unknowns)
                )

        except Exception as err:
            raise Exception(
                "catalog service use_db set to false but no archive_data_dir is set, or is unavailable - exception: "
                + str(err)
            )

        return True

    def uri_for(self, userId, bucket, key):
        return "{}://{}".format(
            self.__uri_scheme__, self._get_archive_filepath(userId, bucket, key)
        )

    def put(self, userId, bucket, key, data):
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            uri = self.uri_for(userId, bucket, key)

            if not self._save_content(uri, data):
                raise Exception("Failed writing file content to disk: {}".format(uri))
            else:
                return uri
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err

    def _save_content(self, uri, data):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        archive_file = parsed.path

        try:
            archive_path = os.path.dirname(archive_file)
            if not os.path.exists(archive_path):
                os.makedirs(archive_path)
        except Exception as err:
            logger.error(
                "cannot create archive data directory - exception: " + str(err)
            )
            raise err

        with open(archive_file, "wb") as OFH:
            data = utils.ensure_bytes(data)
            OFH.write(data)
            return True

    def _load_content(self, path):
        with open(path, "rb") as f:
            return f.read()

    def get(self, userId, bucket, key):
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            return self.get_by_uri(self.uri_for(userId, bucket, key))

        except Exception as err:
            logger.debug("cannot get data: exception - " + str(err))
            raise err

    def _parse_uri(self, uri):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        return parsed.path

    def get_by_uri(self, uri):
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            path = self._parse_uri(uri)
            content = self._load_content(path)
            ret = utils.ensure_bytes(content)
            return ret
        except Exception as e:
            raise ObjectKeyNotFoundError(userId="", bucket="", key="", caused_by=e)

    def delete_by_uri(self, uri):
        archive_file = self._parse_uri(uri)
        if os.path.exists(archive_file):
            try:
                os.remove(archive_file)
                return True
            except Exception as err:
                logger.error(
                    "could not delete archive file ("
                    + str(archive_file)
                    + ") - exception: "
                    + str(err)
                )

    def delete(self, userId, bucket, key):
        if not self.initialized:
            raise Exception("archive not initialized")

        try:
            archive_file = self._get_archive_filepath(userId, bucket, key)
            if os.path.exists(archive_file):
                try:
                    os.remove(archive_file)
                    return True
                except Exception as err:
                    logger.error(
                        "could not delete archive file ("
                        + str(archive_file)
                        + ") - exception: "
                        + str(err)
                    )

        except Exception as err:
            raise err

    def _get_archive_filepath(self, userId, bucket, key):
        filehash = hashlib.md5(key.encode("utf8")).hexdigest()
        fkey = filehash[0:2]
        archive_path = os.path.join(
            self.data_volume,
            hashlib.md5(userId.encode("utf8")).hexdigest(),
            bucket,
            fkey,
        )
        return os.path.join(archive_path, filehash + ".json")
