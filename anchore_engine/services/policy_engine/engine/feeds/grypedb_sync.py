import threading
from types import TracebackType
from typing import Optional, Type

import sqlalchemy

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.db import GrypeDBMetadata, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.feeds.storage import (
    GrypeDBFile,
    GrypeDBStorage,
)
from anchore_engine.subsys import logger

LOCK_AQUISITION_TIMEOUT = 60


class GrypeDBSyncError(Exception):
    pass


class TooManyActiveGrypeDBs(GrypeDBSyncError):
    def __init__(self):
        super().__init__(
            "Could not determine correct grypedb to sync because too many active dbs found in database"
        )


class NoActiveGrypeDB(GrypeDBSyncError):
    def __init__(self):
        super().__init__(
            "Could not determine correct grypedb to sync because no active db found in the database"
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

    @classmethod
    def _get_active_grypedb(cls) -> GrypeDBMetadata:
        """
        Returns active grypedb instance from db. Raises NoActiveGrypeDB if there are none and raises
        TooManyActiveGrypeDBs if more than one

        return: Active GrypeDBMetadata
        rtype: GrypeDBMetadata
        """
        try:
            active_grypedb = cls._query_active_dbs()
        except sqlalchemy.orm.exc.MultipleResultsFound:
            logger.error("Too many active grype dbs found in db")
            raise TooManyActiveGrypeDBs

        if not active_grypedb:
            logger.error("No active grype db found in the database")
            raise NoActiveGrypeDB

        return active_grypedb

    @classmethod
    def _query_active_dbs(cls) -> Optional[GrypeDBMetadata]:
        """
        Runs query against db to get active dbs. Uses one_or_none so raises error if more than one active db

        return: Instance of GrypeDBMetadata or None
        rtype: GrypeDBMetadata
        """
        db = get_thread_scoped_session()
        return (
            db.query(GrypeDBMetadata)
            .filter(GrypeDBMetadata.active == True)
            .one_or_none()
        )

    @classmethod
    def _get_local_grypedb_checksum(cls) -> str:
        """
        Returns checksum of grypedb on local instance

        return: Checksum of local grypedb
        rtype: str
        """
        # get local grypedb checksum
        # Wrapper raises ValueError if grypedb has not been initialized
        try:
            return GrypeWrapperSingleton.get_instance().get_current_grype_db_checksum()
        except ValueError:
            return None

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
                    grypedb_file_path,
                    active_grypedb.archive_checksum,
                    active_grypedb.schema_version,
                )
            else:
                catalog_client = internal_client_for(CatalogClient, userId=None)
                bucket, archive_id = active_grypedb.object_url.split("/")[-2::]
                grypedb_document = catalog_client.get_raw_object(bucket, archive_id)

                # verify integrity of data, create tempfile, and pass path to facade
                GrypeDBFile.verify_integrity(
                    grypedb_document, active_grypedb.archive_checksum
                )
                with GrypeDBStorage() as grypedb_file:
                    with grypedb_file.create_file(active_grypedb.archive_checksum) as f:
                        f.write(grypedb_document)
                    GrypeWrapperSingleton.get_instance().init_grype_db_engine(
                        grypedb_file.path,
                        active_grypedb.archive_checksum,
                        active_grypedb.schema_version,
                    )
        except Exception as e:
            logger.exception("GrypeDBSyncTask failed to sync")
            raise GrypeDBSyncError(str(e)) from e

    @staticmethod
    def _is_sync_necessary(
        active_grypedb: GrypeDBMetadata, local_grypedb_checksum: str
    ) -> bool:
        """
        Returns bool based upon comparisons between the active grype db and the local checksum passed to the function
        """
        if (
            not active_grypedb.archive_checksum
            or local_grypedb_checksum == active_grypedb.archive_checksum
        ):
            logger.info("No Grype DB sync needed at this time")
            return False

        return True

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
        active_grypedb = cls._get_active_grypedb()
        local_grypedb_checksum = cls._get_local_grypedb_checksum()
        is_sync_necessary = cls._is_sync_necessary(
            active_grypedb, local_grypedb_checksum
        )
        if not is_sync_necessary:
            return False

        with GrypeDBSyncLock(LOCK_AQUISITION_TIMEOUT):
            # Need to requery and recheck the active an local checksums because data may have changed since waiting
            # on lock
            active_grypedb = cls._get_active_grypedb()
            local_grypedb_checksum = cls._get_local_grypedb_checksum()
            is_sync_necessary = cls._is_sync_necessary(
                active_grypedb, local_grypedb_checksum
            )

            if is_sync_necessary:
                logger.info(
                    "Grypedb sync is needed to replace local db with checksum %s with current active db with checksum %s",
                    active_grypedb.archive_checksum,
                    local_grypedb_checksum,
                )
                cls._update_grypedb(
                    active_grypedb=active_grypedb,
                    grypedb_file_path=grypedb_file_path,
                )
                return True
            else:
                return False
