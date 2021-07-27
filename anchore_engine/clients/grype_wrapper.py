import errno
import json
import os
import shlex
import shutil
import tarfile
from contextlib import contextmanager
from dataclasses import dataclass
from json.decoder import JSONDecodeError
from typing import Dict, Optional, Tuple

import sqlalchemy
from readerwriterlock import rwlock
from sqlalchemy import Column, ForeignKey, Integer, String, and_, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import anchore_engine.configuration.localconfig
from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys import logger
from anchore_engine.utils import CommandException, run_check

VULNERABILITIES = "vulnerabilities"
VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"
Base = declarative_base()


# Table definitions.
class GrypeVulnerability(Base, UtilMixin):
    __tablename__ = VULNERABILITY_TABLE_NAME

    pk = Column(Integer, primary_key=True)
    id = Column(String)
    package_name = Column(String)
    namespace = Column(String)
    version_constraint = Column(String)
    version_format = Column(String)
    cpes = Column(String)
    related_vulnerabilities = Column(String)
    fixed_in_versions = Column(String)
    fix_state = Column(String)
    advisories = Column(String)

    @property
    def deserialized_related_vulnerabilities(self):
        return json.loads(self.related_vulnerabilities)

    @property
    def deserialized_fixed_in_versions(self):
        return json.loads(self.fixed_in_versions)


class GrypeVulnerabilityMetadata(Base, UtilMixin):
    __tablename__ = VULNERABILITY_METADATA_TABLE_NAME

    id = Column(String, ForeignKey(f"{VULNERABILITY_TABLE_NAME}.id"), primary_key=True)
    namespace = Column(String, primary_key=True)
    data_source = Column(String)
    record_source = Column(String)
    severity = Column(String)
    urls = Column(String)
    description = Column(String)
    cvss = Column(String)

    @property
    def deserialized_urls(self):
        return json.loads(self.urls)

    @property
    def deserialized_cvss(self):
        return json.loads(self.cvss)


@dataclass
class GrypeDBMetadata:
    built: str
    version: str
    checksum: str

    @staticmethod
    def to_object(db_metadata: dict):
        """
        Convert a dict object into a GrypeDBMetadata
        """
        return GrypeDBMetadata(**db_metadata)


@dataclass
class GrypeDBEngineMetadata:
    db_checksum: str
    archive_checksum: str
    grype_db_version: str

    @staticmethod
    def to_object(engine_metadata: dict):
        """
        Convert a dict object into a GrypeEngineMetadata
        """
        return GrypeDBEngineMetadata(**engine_metadata)


@dataclass
class RecordSource:
    count: int
    feed: str
    group: str
    last_synced: str


class LockAcquisitionError(Exception):
    pass


class GrypeWrapperSingleton(object):
    _grype_wrapper_instance = None

    # These values should be treated as constants, and will not be changed by the functions below
    LOCK_READ_ACCESS_TIMEOUT = 60000
    LOCK_WRITE_ACCESS_TIMEOUT = 60000
    SQL_LITE_URL_TEMPLATE = "sqlite:///{}"
    GRYPE_SUB_COMMAND = "grype -vv -o json"
    GRYPE_VERSION_COMMAND = "grype version -o json"
    VULNERABILITY_FILE_NAME = "vulnerability.db"
    METADATA_FILE_NAME = "metadata.json"
    ENGINE_METADATA_FILE_NAME = "engine_metadata.json"
    ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE = "New grype_db archive file not found"
    STAGED_GRYPE_DB_NOT_FOUND_ERROR_MESSAGE = "Unable to promote staged grype_db with archive checksum %s because it was not found."
    GRYPE_BASE_ENV_VARS = {
        "GRYPE_CHECK_FOR_APP_UPDATE": "0",
        "GRYPE_LOG_STRUCTURED": "1",
        "GRYPE_DB_AUTO_UPDATE": "0",
    }
    MISSING_GRYPE_DB_DIR_ERROR_MESSAGE = (
        "Cannot access missing grype_db dir. Reinitialize grype_db."
    )
    MISSING_GRYPE_DB_VERSION_ERROR_MESSAGE = (
        "Cannot access missing grype_db version. Reinitialize grype_db."
    )
    MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE = (
        "Cannot access missing grype_db session maker. Reinitialize grype_db."
    )

    def __new__(cls):
        # If the singleton has not been initialized yet, do so with the instance variables below
        if cls._grype_wrapper_instance is None:
            logger.debug("Initializing Grype wrapper instance.")
            # The singleton instance, only instantiated once outside of testing
            cls._grype_wrapper_instance = super(GrypeWrapperSingleton, cls).__new__(cls)

            # These variables are mutable, their state can be changed when grype_db is updated
            cls._grype_db_dir_internal = None
            cls._grype_db_version_internal = None
            cls._grype_db_session_maker_internal = None

            # These variables are also mutable. They are for staging updated grye_dbs.
            cls._staging_grype_db_dir_internal = None
            cls._staging_grype_db_version_internal = None
            cls._staging_grype_db_session_maker_internal = None

            # The reader-writer lock for this class
            cls._grype_db_lock = rwlock.RWLockWrite()

        # Return the singleton instance
        return cls._grype_wrapper_instance

    @classmethod
    def get_instance(cls):
        """
        Returns the singleton instance of this class.
        """
        return GrypeWrapperSingleton()

    @property
    def _grype_db_dir(self):
        if self._grype_db_dir_internal is None:
            raise ValueError(self.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE)
        else:
            return self._grype_db_dir_internal

    @_grype_db_dir.setter
    def _grype_db_dir(self, grype_db_dir_internal):
        self._grype_db_dir_internal = grype_db_dir_internal

    @property
    def _grype_db_version(self):
        if self._grype_db_version_internal is None:
            raise ValueError(self.MISSING_GRYPE_DB_VERSION_ERROR_MESSAGE)
        else:
            return self._grype_db_version_internal

    @_grype_db_version.setter
    def _grype_db_version(self, grype_db_version_internal):
        self._grype_db_version_internal = grype_db_version_internal

    @property
    def _grype_db_session_maker(self):
        if self._grype_db_session_maker_internal is None:
            raise ValueError(self.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE)
        else:
            return self._grype_db_session_maker_internal

    @_grype_db_session_maker.setter
    def _grype_db_session_maker(self, grype_db_session_maker_internal):
        self._grype_db_session_maker_internal = grype_db_session_maker_internal

    @property
    def _staging_grype_db_dir(self):
        return self._staging_grype_db_dir_internal

    @_staging_grype_db_dir.setter
    def _staging_grype_db_dir(self, staging_grype_db_dir_internal):
        self._staging_grype_db_dir_internal = staging_grype_db_dir_internal

    @property
    def _staging_grype_db_version(self):
        return self._staging_grype_db_version_internal

    @_staging_grype_db_version.setter
    def _staging_grype_db_version(self, staging_grype_db_version_internal):
        self._staging_grype_db_version_internal = staging_grype_db_version_internal

    @property
    def _staging_grype_db_session_maker(self):
        return self._staging_grype_db_session_maker_internal

    @_staging_grype_db_session_maker.setter
    def _staging_grype_db_session_maker(self, staging_grype_db_session_maker_internal):
        self._staging_grype_db_session_maker_internal = (
            staging_grype_db_session_maker_internal
        )

    @contextmanager
    def read_lock_access(self):
        """
        Get read access to the reader writer lock. Releases the lock after exit the
        context. Any exceptions are passed up.
        """
        logger.debug("Attempting to get read access for the grype_db lock")
        read_lock = self._grype_db_lock.gen_rlock()

        try:
            if read_lock.acquire(timeout=self.LOCK_READ_ACCESS_TIMEOUT):
                logger.debug("Acquired read access for the grype_db lock")
                yield
            else:
                raise LockAcquisitionError(
                    "Unable to acquire read access for the grype_db lock"
                )
        finally:
            if read_lock.locked():
                logger.debug("Releasing read access for the grype_db lock")
                read_lock.release()

    @contextmanager
    def write_lock_access(self):
        """
        Get read access to the reader writer lock. Releases the lock after exit the
        context. y exceptions are passed up.
        """
        logger.debug("Attempting to get write access for the grype_db lock")
        write_lock = self._grype_db_lock.gen_wlock()

        try:
            if write_lock.acquire(timeout=self.LOCK_READ_ACCESS_TIMEOUT):
                logger.debug("Unable to acquire write access for the grype_db lock")
                yield
            else:
                raise LockAcquisitionError(
                    "Unable to acquire write access for the grype_db lock"
                )
        finally:
            if write_lock.locked():
                logger.debug("Releasing write access for the grype_db lock")
                write_lock.release()

    @contextmanager
    def grype_session_scope(self, use_staging: bool = False):
        """
        Provides simplified session scope management around the currently configured grype db. Grype
        wrapper only reads from this db (writes only ever happen upstream when the db file is created!)
        so there's no need for normal transaction management as there will never be changes to commit.
        This context manager primarily ensures the session is closed after use.
        """
        if use_staging:
            session = self._staging_grype_db_session_maker()
        else:
            session = self._grype_db_session_maker()

        logger.debug("Opening grype_db session: " + str(session))
        try:
            yield session
        except Exception as exception:
            raise exception
        finally:
            logger.debug("Closing grype_db session: " + str(session))
            session.close()

    @staticmethod
    def read_file_to_json(file_path: str) -> json:
        """
        Static helper function that accepts a file path, ensures it exists, and then reads the contents as json.
        This logs an error and returns None if the file does not exist or cannot be parsed into json, otherwise
        it returns the json.
        """
        # If the file does not exist, log an error and return None
        if not os.path.exists(file_path):
            logger.error(
                "Unable to read non-exists file at %s to json.",
                file_path,
            )
            return None
        else:
            # Get the contents of the file
            with open(file_path) as read_file:
                try:
                    return json.load(read_file)
                except JSONDecodeError:
                    logger.error(
                        "Unable to parse file at %s into json.",
                        file_path,
                    )
                    return None

    def get_current_grype_db_checksum(self):
        """
        Return the checksum for the in-use version of grype db from the dir base name
        """
        if self._grype_db_dir and os.path.exists(self._grype_db_dir):
            grype_db_checksum = os.path.basename(self._grype_db_dir)
        else:
            grype_db_checksum = None
        logger.info("Returning current grype_db checksum: %s", grype_db_checksum)
        return grype_db_checksum

    @staticmethod
    def _get_default_grype_db_dir_from_config():
        """
        Get the default grype db dir from config, and create it if it does not exist.
        """
        localconfig = anchore_engine.configuration.localconfig.get_config()
        if "grype_db_dir" in localconfig:
            local_grype_db_dir = os.path.join(
                localconfig["service_dir"], localconfig["grype_db_dir"]
            )
        else:
            local_grype_db_dir = os.path.join(localconfig["service_dir"], "grype_db/")

        if not os.path.exists(local_grype_db_dir):
            os.mkdir(local_grype_db_dir)

        return local_grype_db_dir

    def _move_grype_db_archive(
        self, grype_db_archive_local_file_location: str, output_dir: str
    ) -> str:
        # Get the location to move the archive to
        archive_file_name = os.path.basename(grype_db_archive_local_file_location)
        grype_db_archive_copied_file_location = os.path.join(
            output_dir, archive_file_name
        )

        if not os.path.exists(grype_db_archive_local_file_location):
            logger.warn(
                "Unable to move grype_db archive from %s to %s because it does not exist",
                grype_db_archive_local_file_location,
                grype_db_archive_copied_file_location,
            )
            raise FileNotFoundError(
                errno.ENOENT,
                self.ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE,
                grype_db_archive_local_file_location,
            )
        else:
            # Move the archive file
            logger.info(
                "Moving the grype_db archive from %s to %s",
                grype_db_archive_local_file_location,
                grype_db_archive_copied_file_location,
            )
            shutil.copyfile(
                grype_db_archive_local_file_location,
                grype_db_archive_copied_file_location,
            )
            return grype_db_archive_copied_file_location

    def _open_grype_db_archive(
        self,
        grype_db_archive_copied_file_location: str,
        parent_dir: str,
        archive_checksum: str,
        grype_db_version: str,
    ) -> str:
        grype_db_parent_dir = os.path.join(parent_dir, archive_checksum)
        grype_db_versioned_dir = os.path.join(grype_db_parent_dir, grype_db_version)
        if not os.path.exists(grype_db_versioned_dir):
            os.makedirs(grype_db_versioned_dir)

        logger.info(
            "Unpacking the grype_db archive with checksum: %s and db version: %s at %s into %s",
            archive_checksum,
            grype_db_version,
            grype_db_archive_copied_file_location,
            grype_db_parent_dir,
        )

        # Put the extracted files in the versioned dir
        with tarfile.open(grype_db_archive_copied_file_location) as read_archive:
            read_archive.extractall(grype_db_versioned_dir)

        # Return the full path to the parent grype_db dir. This is the dir we actually pass to grype,
        # which expects the version subdirectory to be under it.
        logger.info("Returning the unpacked grype_db dir at %s", grype_db_parent_dir)
        return grype_db_parent_dir

    def _write_engine_metadata_to_file(
        self, latest_grype_db_dir: str, archive_checksum: str, grype_db_version: str
    ):
        """
        Write engine metadata to file. This file will contain a json with the values
        for archive_checksum and grype_db_version for the current;y configured grype_db.

        This method writes that file to the same dir the grype_db archive was unpacked at
        in _open_grype_db_archive(). This means that it assumes the dir already exists,
        and does not check to see if it needs to be created prior to writing to it.
        """
        # Get the db checksum and add it below
        metadata_file = os.path.join(
            latest_grype_db_dir, grype_db_version, self.METADATA_FILE_NAME
        )
        db_checksum = None
        if metadata := self.read_file_to_json(metadata_file):
            db_checksum = metadata.get("checksum", None)

        # Write the engine metadata file in the same dir as the ret of the grype db files
        output_file = os.path.join(
            latest_grype_db_dir, grype_db_version, self.ENGINE_METADATA_FILE_NAME
        )

        # Assemble the engine metadata json
        engine_metadata = {
            "archive_checksum": archive_checksum,
            "db_checksum": db_checksum,
            "grype_db_version": grype_db_version,
        }

        # Write engine_metadata to file at output_file
        with open(output_file, "w") as write_file:
            json.dump(engine_metadata, write_file)

        return

    def _remove_grype_db_archive(self, grype_db_archive_local_file_location: str):
        logger.info(
            "Removing the now-unpacked grype_db archive at %s",
            grype_db_archive_local_file_location,
        )
        os.remove(grype_db_archive_local_file_location)

    def _move_and_open_grype_db_archive(
        self,
        grype_db_archive_local_file_location: str,
        archive_checksum: str,
        grype_db_version: str,
    ) -> str:
        """
        This function moves a tarball containing the latest grype db from a location on the local file system
        into the configured grype db dir. It then extracts all files in the tarball and removes the then-unneeded
        archive file.
        """
        # Get the location to copy the archive to
        local_db_dir = self._get_default_grype_db_dir_from_config()

        # Move the archive
        grype_db_archive_copied_file_location = self._move_grype_db_archive(
            grype_db_archive_local_file_location, local_db_dir
        )

        # Unpack the archive
        latest_grype_db_dir = self._open_grype_db_archive(
            grype_db_archive_copied_file_location,
            local_db_dir,
            archive_checksum,
            grype_db_version,
        )

        # Remove the unpacked archive
        self._remove_grype_db_archive(grype_db_archive_copied_file_location)

        # Store the archive_checksum and grype_db_version version in their own metadata file
        self._write_engine_metadata_to_file(
            latest_grype_db_dir, archive_checksum, grype_db_version
        )

        # Return the full path to the grype db file
        return latest_grype_db_dir

    def _init_latest_grype_db_engine(
        self, latest_grype_db_dir: str, grype_db_version: str
    ) -> sqlalchemy.engine:
        """
        Create and return the sqlalchemy engine object
        """
        logger.info(
            "Creating new db engine based on the grype_db at %s", latest_grype_db_dir
        )
        latest_grype_db_file = os.path.join(
            latest_grype_db_dir, grype_db_version, self.VULNERABILITY_FILE_NAME
        )
        db_connect = self.SQL_LITE_URL_TEMPLATE.format(latest_grype_db_file)
        latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=False)
        return latest_grype_db_engine

    def _init_latest_grype_db_session_maker(self, grype_db_engine) -> sessionmaker:
        """
        Create and return the db session maker
        """
        logger.info(
            "Creating new grype_db session maker from engine based on %s",
            grype_db_engine.url,
        )
        return sessionmaker(bind=grype_db_engine)

    def _init_latest_grype_db(
        self,
        lastest_grype_db_archive: str,
        archive_checksum: str,
        grype_db_version: str,
    ) -> Tuple[str, sessionmaker]:
        """
        Write the db string to file, create the engine, and create the session maker
        Return the file and session maker
        """
        latest_grype_db_dir = self._move_and_open_grype_db_archive(
            lastest_grype_db_archive, archive_checksum, grype_db_version
        )
        latest_grype_db_engine = self._init_latest_grype_db_engine(
            latest_grype_db_dir, grype_db_version
        )
        latest_grype_db_session_maker = self._init_latest_grype_db_session_maker(
            latest_grype_db_engine
        )

        # Return the dir and session maker
        return latest_grype_db_dir, latest_grype_db_session_maker

    def _remove_local_grype_db(self, grype_db_dir) -> None:
        """
        Remove old the local grype db file
        """
        if os.path.exists(grype_db_dir):
            logger.info("Removing old grype_db at %s", grype_db_dir)
            shutil.rmtree(grype_db_dir)
        else:
            logger.warn(
                "Failed to remove grype db at %s as it cannot be found.", grype_db_dir
            )
        return

    def update_grype_db(
        self,
        grype_db_archive_local_file_location: str,
        archive_checksum: str,
        grype_db_version: str,
        use_staging: bool = False,
    ) -> Optional[GrypeDBEngineMetadata]:
        """
        Make an update to grype_db, using the provided archive file, archive checksum, and grype db version.
        use_staging determines if this is the active, production grype db used for scanning images and
        querying vulnerability data, or if this is a staging db we are validating before promoting globally.

        Returns the engine metadata for upstream validation.
        """

        if use_staging:
            logger.info(
                "Updating the staging grype_db at %s to archive checksum %s",
                grype_db_archive_local_file_location,
                archive_checksum,
            )
        else:
            logger.info(
                "Updating the production grype_db at %s to archive checksum %s",
                grype_db_archive_local_file_location,
                archive_checksum,
            )

        with self.write_lock_access():
            # Store the db locally and
            # Create the sqlalchemy session maker for the new db
            (
                latest_grype_db_dir,
                latest_grype_db_session_maker,
            ) = self._init_latest_grype_db(
                grype_db_archive_local_file_location, archive_checksum, grype_db_version
            )

            # Store the staged dir and session variables
            if use_staging:
                self._staging_grype_db_dir = latest_grype_db_dir
                self._staging_grype_db_version = grype_db_version
                self._staging_grype_db_session_maker = latest_grype_db_session_maker

                logger.info(
                    "Staging grype_db updated to archive checksum %s",
                    archive_checksum,
                )
            else:
                self._grype_db_dir = latest_grype_db_dir
                self._grype_db_version = grype_db_version
                self._grype_db_session_maker = latest_grype_db_session_maker

                logger.info(
                    "Production grype_db updated to archive checksum %s",
                    archive_checksum,
                )

            # Return the engine metadata as a data object
            return self.get_grype_db_engine_metadata(use_staging=use_staging)

    def unstage_grype_db(self) -> Optional[GrypeDBEngineMetadata]:
        """
        Unstages the staged grype_db. This method returns the production grype_db engine metadata, if a production
        grype_db has been set. Otherwise it returns None.
        """
        self._staging_grype_db_dir = None
        self._staging_grype_db_version = None
        self._staging_grype_db_session_maker = None

        # Return the existing, production engine metadata as a data object
        try:
            return self.get_grype_db_engine_metadata(use_staging=False)
        except ValueError as error:
            logger.warn(
                "Cannot return production grype_db engine metadata, as none has been set."
            )
            return None

    def _get_metadata_file_contents(
        self, metadata_file_name, use_staging: bool = False
    ) -> json:
        """
        Return the json contents of one of the metadata files for the in-use version of grype db
        """
        # Get the path to the latest metadata file, staging or prod
        if use_staging:
            latest_metadata_file = os.path.join(
                self._staging_grype_db_dir,
                self._staging_grype_db_version,
                metadata_file_name,
            )
        else:
            latest_metadata_file = os.path.join(
                self._grype_db_dir, self._grype_db_version, metadata_file_name
            )

        # Ensure the file exists
        return self.read_file_to_json(latest_metadata_file)

    def get_grype_db_metadata(
        self, use_staging: bool = False
    ) -> Optional[GrypeDBMetadata]:
        """
        Return the contents of the current grype_db metadata file as a data object.
        This file contains metadata specific to grype about the current grype_db instance.
        This call can be parameterized to return either the production or staging metadata.
        """

        db_metadata = self._get_metadata_file_contents(
            self.METADATA_FILE_NAME, use_staging=use_staging
        )

        if db_metadata:
            return GrypeDBMetadata.to_object(db_metadata)
        else:
            return None

    def get_grype_db_engine_metadata(
        self, use_staging: bool = False
    ) -> Optional[GrypeDBEngineMetadata]:
        """
        Return the contents of the current grype_db engine metadata file as a data object.
        This file contains metadata specific to engine about the current grype_db instance.
        This call can be parameterized to return either the production or staging metadata.
        """

        engine_metadata = self._get_metadata_file_contents(
            self.ENGINE_METADATA_FILE_NAME, use_staging=use_staging
        )

        if engine_metadata:
            return GrypeDBEngineMetadata.to_object(engine_metadata)
        else:
            return None

    def _get_env_variables(
        self, include_grype_db: bool = True, use_staging: bool = False
    ) -> Dict[str, str]:
        # Set grype env variables, optionally including the grype db location
        grype_env = self.GRYPE_BASE_ENV_VARS.copy()
        if include_grype_db:
            if use_staging:
                grype_env["GRYPE_DB_CACHE_DIR"] = self._staging_grype_db_dir
            else:
                grype_env["GRYPE_DB_CACHE_DIR"] = self._grype_db_dir

        env_variables = os.environ.copy()
        env_variables.update(grype_env)
        return env_variables

    def get_grype_version(self) -> json:
        """
        Return version information for grype
        """
        with self.read_lock_access():
            env_variables = self._get_env_variables(include_grype_db=False)

            logger.debug(
                "Getting grype version with command: %s", self.GRYPE_VERSION_COMMAND
            )

            stdout = None
            err = None
            try:
                stdout, _ = run_check(
                    shlex.split(self.GRYPE_VERSION_COMMAND), env=env_variables
                )
            except CommandException as exc:
                logger.error(
                    "Exception running command: %s, stderr: %s",
                    self.GRYPE_VERSION_COMMAND,
                    exc.stderr,
                )
                raise exc

            # Return the output as json
            return json.loads(stdout)

    def get_vulnerabilities_for_sbom(self, grype_sbom: str) -> json:
        """
        Use grype to scan the provided sbom for vulnerabilites.
        """
        # Get the read lock
        with self.read_lock_access():
            # Get env variables to run the grype scan with
            env_variables = self._get_env_variables()

            # Format and run the command. Grype supports piping in an sbom string
            cmd = "{}".format(self.GRYPE_SUB_COMMAND)

            logger.spew(
                "Running grype with command: {} | {}".format(
                    grype_sbom, self.GRYPE_SUB_COMMAND
                )
            )

            try:
                stdout, _ = run_check(
                    shlex.split(cmd),
                    input_data=grype_sbom,
                    log_level="spew",
                    env=env_variables,
                )
            except CommandException as exc:
                logger.error(
                    "Exception running command: %s, stderr: %s",
                    cmd,
                    exc.stderr,
                )
                raise exc

            # Return the output as json
            return json.loads(stdout)

    def get_vulnerabilities_for_sbom_file(self, grype_sbom_file: str) -> json:
        """
        Use grype to scan the provided sbom for vulnerabilites.
        """
        # Get the read lock
        with self.read_lock_access():
            # Get env variables to run the grype scan with
            env_variables = self._get_env_variables()

            # Format and run the command
            cmd = "{grype_sub_command} sbom:{sbom}".format(
                grype_sub_command=self.GRYPE_SUB_COMMAND, sbom=grype_sbom_file
            )

            logger.debug("Running grype with command: %s", cmd)

            stdout = None
            err = None
            try:
                stdout, _ = run_check(
                    shlex.split(cmd), log_level="spew", env=env_variables
                )
            except CommandException as exc:
                logger.error(
                    "Exception running command: %s, stderr: %s",
                    cmd,
                    exc.stderr,
                )
                raise exc

            # Return the output as json
            return json.loads(stdout)

    def query_vulnerabilities(
        self,
        vuln_id=None,
        affected_package=None,
        affected_package_version=None,
        namespace=None,
    ):
        """
        Query the grype db for vulnerabilites. affected_package_version is unused, but is left in place for now to match the
        header of the existing function this is meant to replace.
        """
        # Get and release read locks
        with self.read_lock_access():
            if type(vuln_id) == str:
                vuln_id = [vuln_id]

            if type(namespace) == str:
                namespace = [namespace]

            logger.debug(
                "Querying grype_db for vuln_id: %s, namespace: %s, affected_package: %s",
                vuln_id,
                namespace,
                affected_package,
            )

            with self.grype_session_scope() as session:
                # GrypeVulnerabilityMetadata contains info for the vulnerability. GrypeVulnerability contains info for the affected/fixed package
                # A vulnerability can impact 0 or more packages i.e. a GrypeVulnerabilityMetadata row can be associated with 0 or more GrypeVulnerability rows
                # Since the lookup is for vulnerability information, the query should left outer join GrypeVulnerabilityMetadata with GrypeVulnerability
                query = session.query(
                    GrypeVulnerability, GrypeVulnerabilityMetadata
                ).outerjoin(
                    GrypeVulnerability,
                    and_(
                        GrypeVulnerability.id == GrypeVulnerabilityMetadata.id,
                        GrypeVulnerability.namespace
                        == GrypeVulnerabilityMetadata.namespace,
                    ),
                )

                if vuln_id is not None:
                    query = query.filter(GrypeVulnerability.id.in_(vuln_id))
                if namespace is not None:
                    query = query.filter(GrypeVulnerability.namespace.in_(namespace))
                if affected_package is not None:
                    query = query.filter(
                        GrypeVulnerability.package_name == affected_package
                    )

                logger.debug("grype_db sql query for vulnerabilities lookup: %s", query)

                return query.all()

    def query_record_source_counts(self, use_staging: bool = False):
        """
        Query the current feed group counts for all current vulnerabilities.
        """
        # Get and release read locks
        with self.read_lock_access():
            logger.debug("Querying grype_db for feed group counts")

            # Get the counts for each record source
            with self.grype_session_scope(use_staging) as session:
                results = (
                    session.query(
                        GrypeVulnerability.namespace,
                        func.count(GrypeVulnerability.namespace).label("count"),
                    )
                    .group_by(GrypeVulnerability.namespace)
                    .all()
                )

                # Get the timestamp from the current metadata file
                last_synced = None
                if db_metadata := self.get_grype_db_metadata(use_staging):
                    last_synced = db_metadata.built

                # Transform the results along with the last_synced timestamp for each result
                output = []
                for group, count in results:
                    record_source = RecordSource(
                        count=count,
                        feed=VULNERABILITIES,
                        group=group,
                        last_synced=last_synced,
                    )
                    output.append(record_source)

                # Return the results
                return output
