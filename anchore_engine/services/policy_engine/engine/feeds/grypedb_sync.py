import threading
from dataclasses import dataclass
from types import TracebackType
from typing import Iterable, Optional, Type

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import GrypeDBMetadata, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.feeds.storage import (
    GrypeDBFile,
    GrypeDBStorage,
)
from anchore_engine.subsys import logger

LOCK_AQUISITION_TIMEOUT = 10


class GrypeDBSyncError(Exception):
    pass


class TooManyActiveGrypeDBs(GrypeDBSyncError):
    def __init__(self):
        super().__init__(
            "Could not determine correct grypedb to sync because too many active dbs found in database"
        )


class GrypeDBSyncLockAquisitionTimeout(GrypeDBSyncError):
    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Aquisition timeout of {self.timeout_seconds} seconds encountered before lock was released. Potential deadlock in system."
        )


class GrypeDBSyncLock:
    _lock = threading.Lock()

    def __init__(self, timeout: int) -> None:
        self.timeout = timeout
        self.lock_acquired: bool = False

    def __enter__(self) -> None:
        self.lock_acquired = self._lock.acquire(timeout=self.timeout)
        if not self.lock_acquired:
            raise GrypeDBSyncLockAquisitionTimeout(self.timeout)

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        if self.lock_acquired:
            self._lock.release()


class GrypeDBSyncManager:
    """
    Sync grype db to local instance of policy engine if it has been updated globally
    """

    lock = threading.Lock()

    @dataclass
    class SyncNecessaryResp:
        sync_necessary: bool
        active_grypedb: Optional[GrypeDBMetadata] = None

    @classmethod
    def _get_active_grypedb(cls) -> Optional[GrypeDBMetadata]:
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
    def _get_local_grypedb_checksum(cls) -> str:
        """
        Returns checksum of grypedb on local instance

        return: Checksum of local grypedb
        rtype: str
        """
        # get local grypedb checksum
        return GrypeWrapperSingleton.get_instance().get_current_grype_db_checksum()

    @classmethod
    def _get_active_grypedb_if_sync_necessary(cls) -> Optional[GrypeDBMetadata]:
        """
        Return the GrypeDBMetadata for the currently active GrypeDB IF a sync is necessary. Return None otherwise.
        :return: GrypeDBMetadata if sync is necessary or None if sync is not necessary
        :rtype: Optional[GrypeDBMetadata]
        """
        active_grypedb = cls._get_active_grypedb()
        if active_grypedb:
            if cls._check_sync_necessary(active_grypedb.checksum):
                return active_grypedb
        return None

    @classmethod
    def _check_sync_necessary(cls, active_grypedb_checksum: str) -> bool:
        """
        Check if a sync is necessary

        :param active_grypedb_checksum: Checksum of currently active Grype DB
        :type active_grypedb_checksum: str
        :return: true if sync is necessary, false if not
        :rtype: bool
        """
        local_grypedb_checksum = cls._get_local_grypedb_checksum()
        sync_needed = local_grypedb_checksum != active_grypedb_checksum
        if not sync_needed:
            logger.info("No Grype DB sync needed at this time")
        else:
            logger.info("Grype DB sync is required.")

        return sync_needed

    @classmethod
    def _update_grypedb(
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
                GrypeWrapperSingleton.get_instance().init_grype_db_engine(
                    grypedb_file_path, active_grypedb.checksum
                )
            else:
                catalog_client = internal_client_for(CatalogClient, userId=None)
                bucket, archive_id = active_grypedb.object_url.split("/")[-2::]
                grypedb_document = catalog_client.get_raw_object(bucket, archive_id)

                # verify integrity of data, create tempfile, and pass path to facade
                GrypeDBFile.verify_integrity(grypedb_document, active_grypedb.checksum)
                with GrypeDBStorage() as grypedb_file:
                    with grypedb_file.create_file(active_grypedb.checksum) as f:
                        f.write(grypedb_document)
                    GrypeWrapperSingleton.get_instance().init_grype_db_engine(
                        grypedb_file.path, active_grypedb.checksum
                    )
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
        # Do an initial check outside of lock to determine if sync is necessary
        # Helps ensure that synchronous processes are not slowed by lock
        if not cls._get_active_grypedb_if_sync_necessary():
            return False
        with GrypeDBSyncLock(LOCK_AQUISITION_TIMEOUT):
            active_grypedb = cls._get_active_grypedb_if_sync_necessary()
            if active_grypedb:
                cls._update_grypedb(
                    active_grypedb=active_grypedb,
                    grypedb_file_path=grypedb_file_path,
                )
                return True
            else:
                return False
