import anchore_engine.configuration.localconfig
import errno
import json
import os
import shlex
import shutil
import sqlalchemy
import tarfile

from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys import logger
from anchore_engine.utils import CommandException, run_check, run_piped_command_list
from contextlib import contextmanager
from dataclasses import dataclass
from json.decoder import JSONDecodeError
from readerwriterlock import rwlock
from sqlalchemy import Column, ForeignKey, func, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"
Base = declarative_base()


# Table definitions.
class GrypeVulnerability(Base, UtilMixin):
    __tablename__ = VULNERABILITY_TABLE_NAME

    pk = Column(Integer, primary_key=True)
    id = Column(String)
    record_source = Column(String)
    package_name = Column(String)
    namespace = Column(String)
    version_constraint = Column(String)
    version_format = Column(String)
    cpes = Column(String)
    proxy_vulnerabilities = Column(String)
    fixed_in_version = Column(String)
    vulnerability_metadata = relationship("GrypeVulnerabilityMetadata")


class GrypeVulnerabilityMetadata(Base, UtilMixin):
    __tablename__ = VULNERABILITY_METADATA_TABLE_NAME

    id = Column(String, ForeignKey(f"{VULNERABILITY_TABLE_NAME}.id"), primary_key=True)
    record_source = Column(String, primary_key=True)
    severity = Column(String)
    links = Column(String)
    description = Column(String)
    cvss_v2 = Column(String)
    cvss_v3 = Column(String)


@dataclass
class RecordSource:
    count: int
    feed: str
    group: str
    last_synced: str


class GrypeWrapperSingleton(object):
    _grype_wrapper_instance = None

    # These values should be treated as constants, and will not be changed by the functions below
    LOCK_READ_ACCESS_TIMEOUT = 60
    LOCK_WRITE_ACCESS_TIMEOUT = 60
    GRYPE_SUB_COMMAND = "grype -vv -o json"
    GRYPE_VERSION_COMMAND = "grype version -o json"
    VULNERABILITY_FILE_NAME = "vulnerability.db"
    METADATA_FILE_NAME = "metadata.json"
    ENGINE_METADATA_FILE_NAME = "engine_metadata.json"
    ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE = "New grype_db archive file not found"
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
            # The singleton instance, only instantiated once outside of testing
            cls._grype_wrapper_instance = super(GrypeWrapperSingleton, cls).__new__(cls)

            # These variables are mutable, their state can be changed when grype_db is updated
            cls._grype_db_dir_internal = None
            cls._grype_db_version_internal = None
            cls._grype_db_session_maker_internal = None

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
    def _grype_db_dir(self, _grype_db_dir_internal):
        self._grype_db_dir_internal = _grype_db_dir_internal

    @property
    def _grype_db_version(self):
        if self._grype_db_version_internal is None:
            raise ValueError(self.MISSING_GRYPE_DB_VERSION_ERROR_MESSAGE)
        else:
            return self._grype_db_version_internal

    @_grype_db_version.setter
    def _grype_db_version(self, _grype_db_version_internal):
        self._grype_db_version_internal = _grype_db_version_internal

    @property
    def _grype_db_session_maker(self):
        if self._grype_db_session_maker_internal is None:
            raise ValueError(self.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE)
        else:
            return self._grype_db_session_maker_internal

    @_grype_db_session_maker.setter
    def _grype_db_session_maker(self, _grype_db_session_maker_internal):
        self._grype_db_session_maker_internal = _grype_db_session_maker_internal

    @contextmanager
    def read_lock_access(self):
        """
        Get read access to the reader writer lock. Releases the lock after exit the
        context. Any exceptions are passed up.
        """
        logger.debug("Getting read access for the grype_db lock")
        read_lock = self._grype_db_lock.gen_rlock()

        try:
            yield read_lock.acquire(
                blocking=False, timeout=self.LOCK_READ_ACCESS_TIMEOUT
            )
        except Exception as exception:
            raise exception
        finally:
            logger.debug("Releasing read access for the grype_db lock")
            read_lock.release()

    @contextmanager
    def write_lock_access(self):
        """
        Get read access to the reader writer lock. Releases the lock after exit the
        context. y exceptions are passed up.
        """
        logger.debug("Getting write access for the grype_db lock")
        write_lock = self._grype_db_lock.gen_wlock()

        try:
            yield write_lock.acquire(
                blocking=True, timeout=self.LOCK_WRITE_ACCESS_TIMEOUT
            )
        except Exception as exception:
            raise exception
        finally:
            logger.debug("Releasing write access for the grype_db lock")
            write_lock.release()

    @contextmanager
    def grype_session_scope(self):
        """
        Provides simplified session scope management around the currently configured grype db. Grype
        wrapper only reads from this db (writes only ever happen upstream when the db file is created!)
        so there's no need for normal transaction management as there will never be changes to commit.
        This context manager primarily ensures the session is closed after use.
        """
        session = self._grype_db_session_maker()

        logger.debug("Opening grype_db session: " + str(session))
        try:
            yield session
        except Exception as exception:
            raise exception
        finally:
            logger.debug("Closing grype_db session: " + str(session))
            session.close()

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
            os.replace(
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

        # Write the engine metadata file in the same dir as the ret of the grype db files
        output_file = os.path.join(
            latest_grype_db_dir, grype_db_version, self.ENGINE_METADATA_FILE_NAME
        )

        # Assemble the engine metadata json
        engine_metadata = {
            "archive_checksum": archive_checksum,
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

    def _init_latest_grype_db_engine(self, latest_grype_db_dir, grype_db_version):
        """
        Create and return the sqlalchemy engine object
        """
        logger.info(
            "Creating new db engine based on the grype_db at %s", latest_grype_db_dir
        )
        latest_grype_db_file = os.path.join(
            latest_grype_db_dir, grype_db_version, self.VULNERABILITY_FILE_NAME
        )
        db_connect = "sqlite:///{}".format(latest_grype_db_file)
        latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
        return latest_grype_db_engine

    def _init_latest_grype_db_session_maker(self, grype_db_engine):
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
    ):
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

    def _remove_local_grype_db(self, grype_db_dir):
        """
        Remove old the local grype db file
        """
        if os.path.exists(grype_db_dir):
            logger.info("Removing old grype_db at %s", grype_db_dir)
            shutil.rmtree(grype_db_dir)
        else:
            logger.warning(
                "Failed to remove grype db at %s as it cannot be found.", grype_db_dir
            )
        return

    def init_grype_db_engine(
        self,
        grype_db_archive_local_file_location: str,
        archive_checksum: str,
        grype_db_version: str,
    ):
        """
        Update the installed grype db with the provided definition, and remove the old grype db file.
        This method does not validation of the db, and assumes it has passed any required validation upstream
        """

        logger.info(
            "Updating grype with a new grype_db archive from %s",
            grype_db_archive_local_file_location,
        )

        with self.write_lock_access():
            # Store the db locally and
            # Create the sqlalchemy engine for the new db
            (
                latest_grype_db_dir,
                latest_grype_db_session_maker,
            ) = self._init_latest_grype_db(
                grype_db_archive_local_file_location, archive_checksum, grype_db_version
            )

            # Store the dir and session variables globally
            # For use during reads and to remove in the next update
            try:
                old_grype_db_dir = self._grype_db_dir
            except ValueError:
                old_grype_db_dir = None
            self._grype_db_dir = latest_grype_db_dir
            self._grype_db_version = grype_db_version
            self._grype_db_session_maker = latest_grype_db_session_maker

            # Remove the old local db only if it's not the current db
            if old_grype_db_dir and old_grype_db_dir != self._grype_db_dir:
                self._remove_local_grype_db(old_grype_db_dir)

    def _get_metadata_file_contents(self, metadata_file_name) -> json:
        """
        Return the json contents of one of the metadata files for the in-use version of grype db
        """
        # Get the path to the latest metadata file
        latest_metadata_file = os.path.join(
            self._grype_db_dir, self._grype_db_version, metadata_file_name
        )

        # Ensure the file exists
        if not os.path.exists(latest_metadata_file):
            # If not, return None
            return None
        else:
            # Get the contents of the file
            with open(latest_metadata_file) as read_file:
                try:
                    return json.load(read_file)
                except JSONDecodeError:
                    logger.error(
                        "Unable to decode metadata file into json: %s",
                        read_file,
                    )
                    return None

    def get_current_grype_db_metadata(self) -> json:
        """
        Return the json contents of the current grype_db metadata file.
        This file contains metadata specific to grype about the current grype_db instance.
        """
        return self._get_metadata_file_contents(self.METADATA_FILE_NAME)

    def get_current_grype_db_engine_metadata(self) -> json:
        """
        Return the json contents of the current grype_db engine metadata file.
        This file contains metadata specific to engine about the current grype_db instance.
        """
        return self._get_metadata_file_contents(self.ENGINE_METADATA_FILE_NAME)

    def _get_proc_env(self, include_grype_db=True):
        # Set grype env variables, including the grype db location
        grype_env = {
            "GRYPE_CHECK_FOR_APP_UPDATE": "0",
            "GRYPE_LOG_STRUCTURED": "1",
            "GRYPE_DB_AUTO_UPDATE": "0",
        }
        if include_grype_db:
            grype_env["GRYPE_DB_CACHE_DIR"] = self._grype_db_dir

        proc_env = os.environ.copy()
        proc_env.update(grype_env)
        return proc_env

    def get_grype_version(self) -> json:
        """
        Return version information for grype
        """
        with self.read_lock_access():
            proc_env = self._get_proc_env(include_grype_db=False)

            logger.debug(
                "Getting grype version with command: %s", self.GRYPE_VERSION_COMMAND
            )

            stdout = None
            err = None
            try:
                stdout, _ = run_check(
                    shlex.split(self.GRYPE_VERSION_COMMAND), env=proc_env
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
            proc_env = self._get_proc_env()

            # Format and run the command. Grype supports piping in an sbom string, so we need to this in two steps.
            # 1) Echo the sbom string to std_out
            # 2) Pipe that into grype
            pipe_sub_cmd = "echo '{sbom}'".format(
                sbom=grype_sbom,
            )
            full_cmd = [shlex.split(pipe_sub_cmd), shlex.split(self.GRYPE_SUB_COMMAND)]

            logger.debug(
                "Running grype with command: %s | %s",
                pipe_sub_cmd,
                self.GRYPE_SUB_COMMAND,
            )

            stdout = None
            err = None
            try:
                _, stdout, _ = run_piped_command_list(
                    full_cmd, env=proc_env, sanitize_input=False
                )
            except CommandException as exc:
                logger.error(
                    "Exception running command: %s | %s, stderr: %s",
                    pipe_sub_cmd,
                    self.GRYPE_SUB_COMMAND,
                    exc.stderr,
                )
                raise exc

            # Return the output as json
            return json.loads(stdout.decode("utf-8"))

    def get_vulnerabilities_for_sbom_file(self, grype_sbom_file: str) -> json:
        """
        Use grype to scan the provided sbom for vulnerabilites.
        """
        # Get the read lock
        with self.read_lock_access():
            # Get env variables to run the grype scan with
            proc_env = self._get_proc_env()

            # Format and run the command
            cmd = "{grype_sub_command} sbom:{sbom}".format(
                grype_sub_command=self.GRYPE_SUB_COMMAND, sbom=grype_sbom_file
            )

            logger.debug("Running grype with command: %s", cmd)

            stdout = None
            err = None
            try:
                stdout, _ = run_check(shlex.split(cmd), env=proc_env)
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
                query = session.query(GrypeVulnerability).join(
                    GrypeVulnerabilityMetadata,
                    GrypeVulnerability.id == GrypeVulnerabilityMetadata.id,
                )

                if vuln_id is not None:
                    query = query.filter(GrypeVulnerability.id.in_(vuln_id))
                if namespace is not None:
                    query = query.filter(GrypeVulnerability.namespace.in_(namespace))
                if affected_package is not None:
                    query = query.filter(
                        GrypeVulnerability.package_name == affected_package
                    )

                return query.all()

    def query_record_source_counts(self):
        """
        Query the current feed group counts for all current vulnerabilities.
        """
        # Get and release read locks
        with self.read_lock_access():
            logger.debug("Querying grype_db for feed group counts")

            # Get the counts for each record source
            with self.grype_session_scope() as session:
                results = (
                    session.query(
                        GrypeVulnerability.record_source,
                        func.count(GrypeVulnerability.record_source).label("count"),
                    )
                    .group_by(GrypeVulnerability.record_source)
                    .all()
                )

                # Get the timestamp from the current metadata file
                metadata = self.get_current_grype_db_metadata()
                last_synced = metadata["built"]

                # Transform the results along with the last_synced timestamp for each result
                output = []
                for result in results:
                    feed_group = str(result[0]).split(":", 1)
                    if len(feed_group) != 2:
                        logger.error(
                            "Unable to process feed/group for record_source {}. Omitting from the response".format(
                                feed_group
                            )
                        )
                        continue

                    record_source = RecordSource(
                        count=result[1],
                        feed=feed_group[0],
                        group=feed_group[1],
                        last_synced=last_synced,
                    )
                    output.append(record_source)

                # Return the results
                return output
