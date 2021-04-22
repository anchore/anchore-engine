import threading
from typing import Iterable, Optional

from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import GrypeDBMetadata, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.feeds.storage import (
    GrypeDBFile,
    GrypeDBStorage,
)
from anchore_engine.subsys import logger


class GrypeDBSyncError(Exception):
    pass


class TooManyActiveGrypeDBs(GrypeDBSyncError):
    def __init__(self):
        super().__init__(
            "Could not determine correct grypedb to sync because too many active dbs found in database"
        )


class GrypeDBSyncManager:
    """
    Sync grype db to local instance of policy engine if it has been updated globally
    """

    lock = threading.Lock()

    @classmethod
    def get_active_grypedb(cls) -> Optional[GrypeDBMetadata]:
        """
        Returns active grybdb instance from db. Returns None if there are none and raises exception if more than one

        return: Instance of active GrypeDBMetadata or None
        rtype: [GrypeDBMetadata, None]
        """
        active_grypedbs = cls._query_active_dbs()

        if len(active_grypedbs) == 0:
            return None
        elif len(active_grypedbs) > 1:
            logger.exception("Too many active grypdbs found in db")
            raise TooManyActiveGrypeDBs
        else:
            return active_grypedbs[0]

    @classmethod
    def _query_active_dbs(cls) -> Iterable[GrypeDBMetadata]:
        """
        Runs query against db to get active dbs

        return: Array of GrypeDBMetadatas
        rtype: list
        """
        db = get_thread_scoped_session()
        return db.query(GrypeDBMetadata).filter(GrypeDBMetadata.active == True).all()

    @classmethod
    def get_local_grypedb_checksum(cls) -> str:
        """
        Returns checksum of grypedb on local instance

        return: Checksum of local grypedb
        rtype: str
        """
        # get local grypedb checksum
        # TODO Will use the grype facade once implemented
        # return grype_wrapper.get_current_grype_db_checksum()
        return ""

    @classmethod
    def update_grypedb(
        cls,
        active_grypedb: GrypeDBMetadata,
        grypedb_file_path: Optional[str] = None,
    ):
        """
        Runs GrypeDBSyncTask on instance. If file_path present, passes this to grype facade to update
        If not, it builds the catalog url, gets the raw document and saves it to tempfile and passes path to grype facade
        """
        try:
            if grypedb_file_path:
                # TODO Pass the path directly to the facade
                logger.info("Pass to facade with file path")
                # grype_wrapper.update_grype_db(self.grypedb_file_path, self.active_grypedb.checksum)
            else:
                catalog_client = internal_client_for(CatalogClient, userId=None)
                grypedb_document = catalog_client.get_raw_document(
                    active_grypedb.bucket, active_grypedb.archive_id
                )

                # verify integrity of data, create tempfile, and pass path to facade
                GrypeDBFile.verify_integrity(grypedb_document, active_grypedb.checksum)
                with GrypeDBStorage() as grypedb_file:
                    with grypedb_file.create_file(active_grypedb.checksum) as f:
                        f.write(grypedb_document)
                    # TODO pass file path to grype facade
                    logger.info("Pass to facade with created file path")
                    # grype_wrapper.update_grype_db(grypedb_file.path, self.active_grypedb.checksum)
        except Exception as e:
            logger.exception("GrypeDBSyncTask failed to sync")
            raise GrypeDBSyncError(str(e)) from e

    @classmethod
    def run_grypedb_sync(cls, grypedb_file_path: Optional[str] = None):
        """
        Runs GrypeDBSyncTask if it is necessary. Determines this by comparing local db checksum with active one in DB
        Returns true or false based upon whether db updated

        :param grypedb_file_path: Can be passed a fie path to existing grypedb to use on local disk
        return: Boolean to whether the db was updated or not
        rtype: bool
        """
        try:
            with cls.lock:
                active_grypedb = cls.get_active_grypedb()
                if not active_grypedb:
                    logger.info("No active grypedb available in the system to sync")
                    return False

                local_grypedb_checksum = cls.get_local_grypedb_checksum()

                if local_grypedb_checksum != active_grypedb.checksum:
                    cls.update_grypedb(
                        active_grypedb=active_grypedb,
                        grypedb_file_path=grypedb_file_path,
                    )
                    return True
                else:
                    logger.info("No grypedb sync needed at this time")
                    return False
        except GrypeDBSyncError as e:
            logger.exception("Error executing grypedb sync task {}".format(str(e)))
            raise
