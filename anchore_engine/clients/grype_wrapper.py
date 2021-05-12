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

    GRYPE_SUB_CMD = "grype -vv -o json"
    VULNERABILITY_FILE_NAME = "vulnerability.db"
    METADATA_FILE_NAME = "metadata.json"
    ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE = "New grype_db archive file not found"
    MISSING_GRYPE_DB_DIR_ERROR_MESSAGE = (
        "Cannot access missing grype_db_dir. Reinitialize grype_db."
    )
    MISSING_GRYPE_DB_SESSION_ERROR_MESSAGE = (
        "Cannot access missing grype_db_session. Reinitialize grype_db."
    )

    def __new__(cls):
        if cls._grype_wrapper_instance is None:
            cls._grype_wrapper_instance = super(GrypeWrapperSingleton, cls).__new__(cls)
            cls._grype_db_dir = None
            cls._grype_db_session = None
            cls._grype_db_lock = rwlock.RWLockWrite()
        return cls._grype_wrapper_instance

    def get_current_grype_db_checksum(self):
        """
        Return the checksum for the in-use version of grype db
        """
        grype_db_dir = self._get_grype_db_dir()
        if grype_db_dir and os.path.exists(grype_db_dir):
            grype_db_checksum = os.path.basename(grype_db_dir)
        else:
            grype_db_checksum = None
        logger.info("Returning current grype_db checksum: {}".format(grype_db_checksum))
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
                "Unable to move grype_db archive from {} to {} because it does not exist".format(
                    grype_db_archive_local_file_location,
                    grype_db_archive_copied_file_location,
                )
            )
            raise FileNotFoundError(
                errno.ENOENT,
                self.ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE,
                grype_db_archive_local_file_location,
            )
        else:
            # Move the archive file
            logger.info(
                "Moving the grype_db archive from {} to {}".format(
                    grype_db_archive_local_file_location,
                    grype_db_archive_copied_file_location,
                )
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
        version_name: str,
    ) -> str:
        output_dir = os.path.join(parent_dir, version_name)
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)

        logger.info(
            "Unpacking the grype_db archive at {} into {}".format(
                grype_db_archive_copied_file_location, output_dir
            )
        )

        # Put the extracted files in the same dir as the archive
        with tarfile.open(grype_db_archive_copied_file_location) as read_archive:
            read_archive.extractall(output_dir)

        # Return the full path to the grype_db dir
        logger.info("Returning the unpacked grype_db dir at {}".format(output_dir))
        return output_dir

    def _remove_grype_db_archive(self, grype_db_archive_local_file_location: str):
        logger.info(
            "Removing the now-unpacked grype_db archive at {}".format(
                grype_db_archive_local_file_location
            )
        )
        os.remove(grype_db_archive_local_file_location)

    def _move_and_open_grype_db_archive(
        self, grype_db_archive_local_file_location: str, version_name: str
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
            grype_db_archive_copied_file_location, local_db_dir, version_name
        )

        # Remove the unpacked archive
        self._remove_grype_db_archive(grype_db_archive_copied_file_location)

        # Return the full path to the grype db file
        return latest_grype_db_dir

    def _init_latest_grype_db_engine(self, latest_grype_db_dir):
        """
        Create and return the sqlalchemy engine object
        """
        logger.info(
            "Creating new db engine based on the grype_db at {}".format(
                latest_grype_db_dir
            )
        )
        latest_grype_db_file = os.path.join(
            latest_grype_db_dir, self.VULNERABILITY_FILE_NAME
        )
        db_connect = "sqlite:///{}".format(latest_grype_db_file)
        latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
        return latest_grype_db_engine

    def _init_latest_grype_db_session(self, grype_db_engine):
        """
        Create and return the db session
        """
        logger.info(
            "Creating new grype_db session from engine based on {}".format(
                grype_db_engine.url
            )
        )
        SessionMaker = sessionmaker(bind=grype_db_engine)
        grype_db_session = SessionMaker()
        return grype_db_session

    def _init_latest_grype_db(self, lastest_grype_db_archive: str, version_name: str):
        """
        Write the db string to file, create the engine, and create the session
        Return the file and session
        """
        latest_grype_db_dir = self._move_and_open_grype_db_archive(
            lastest_grype_db_archive, version_name
        )
        latest_grype_db_engine = self._init_latest_grype_db_engine(latest_grype_db_dir)
        latest_grype_db_session = self._init_latest_grype_db_session(
            latest_grype_db_engine
        )

        # Return the dir, file, and engine
        return latest_grype_db_dir, latest_grype_db_session

    def _remove_local_grype_db(self, grype_db_dir):
        """
        Remove old the local grype db file
        """
        if os.path.exists(grype_db_dir):
            logger.info("Removing old grype_db at {}".format(grype_db_dir))
            shutil.rmtree(grype_db_dir)
        else:
            logger.error(
                "Failed to remove grype db at {} as it cannot be found.".format(
                    grype_db_dir
                )
            )
        return

    def init_grype_db_engine(
        self, grype_db_archive_local_file_location: str, version_name: str
    ):
        """
        Update the installed grype db with the provided definition, and remove the old grype db file.
        This method does not validation of the db, and assumes it has passed any required validation upstream
        """

        logger.info(
            "Updating grype with a new grype_db archive from {}".format(
                grype_db_archive_local_file_location
            )
        )

        write_lock = self._grype_db_lock.gen_wlock()
        if write_lock.acquire(blocking=True, timeout=60):
            try:

                # Store the db locally and
                # Create the sqlalchemy engine for the new db
                (
                    latest_grype_db_dir,
                    latest_grype_db_session,
                ) = self._init_latest_grype_db(
                    grype_db_archive_local_file_location, version_name
                )

                # Store the dir and session variables globally
                # For use during reads and to remove in the next update
                old_grype_db_dir = self._grype_db_dir
                self._grype_db_dir = latest_grype_db_dir
                self._grype_db_session = latest_grype_db_session

                # Remove the old local db only if it's not the current db
                if old_grype_db_dir and old_grype_db_dir != self._grype_db_dir:
                    self._remove_local_grype_db(old_grype_db_dir)
            finally:
                write_lock.release()

    def get_current_grype_db_metadata(self) -> json:
        """
        Return the json contents of the metadata file for the in-use version of grype db
        """
        # Get the path to the latest grype_db metadata file
        latest_grype_db_metadata_file = os.path.join(
            self._grype_db_dir, self.METADATA_FILE_NAME
        )

        # Ensure the file exists
        if not os.path.exists(latest_grype_db_metadata_file):
            # If not, return None
            return None
        else:
            # Get the contents of the file
            with open(latest_grype_db_metadata_file) as read_file:
                try:
                    return json.load(read_file)
                except JSONDecodeError:
                    logger.error(
                        "Unable to decode grype_db metadata file into json: %s",
                        read_file,
                    )
                    return None

    def _get_proc_env(self):
        # Set grype env variables, including the grype db location
        grype_env = {
            "GRYPE_CHECK_FOR_APP_UPDATE": "0",
            "GRYPE_LOG_STRUCTURED": "1",
            "GRYPE_DB_AUTO_UPDATE": "0",
            "GRYPE_DB_CACHE_DIR": "{}".format(self._grype_db_dir),
        }
        proc_env = os.environ.copy()
        proc_env.update(grype_env)
        return proc_env

    def get_vulnerabilities_for_sbom(self, grype_sbom: str) -> json:
        """
        Use grype to scan the provided sbom for vulnerabilites.
        """
        # Get the read lock
        read_lock = self._grype_db_lock.gen_rlock()
        if read_lock.acquire(blocking=False, timeout=60):
            try:
                # Get env variables to run the grype scan with
                proc_env = self._get_proc_env()

                # Format and run the command. Grype supports piping in an sbom string, so we need to this in two steps.
                # 1) Echo the sbom string to std_out
                # 2) Pipe that into grype
                pipe_sub_cmd = "echo '{sbom}'".format(
                    sbom=grype_sbom,
                )
                full_cmd = [shlex.split(pipe_sub_cmd), shlex.split(self.GRYPE_SUB_CMD)]

                logger.debug(
                    "Running grype with command: {} | {}".format(
                        pipe_sub_cmd, self.GRYPE_SUB_CMD
                    )
                )

                stdout = None
                err = None
                try:
                    _, stdout, _ = run_piped_command_list(full_cmd, env=proc_env)
                except CommandException as exc:
                    logger.error(
                        "Exception running command: {} | {}, stderr: {}".format(
                            pipe_sub_cmd, self.GRYPE_SUB_CMD, exc.stderr
                        )
                    )
                    raise exc
            finally:
                read_lock.release()

            # Return the output as json
            return json.loads(stdout.decode("utf-8"))

    def get_vulnerabilities_for_sbom_file(self, grype_sbom_file: str) -> json:
        """
        Use grype to scan the provided sbom for vulnerabilites.
        """
        # Get the read lock
        read_lock = self._grype_db_lock.gen_rlock()
        if read_lock.acquire(blocking=False, timeout=60):
            try:
                # Get env variables to run the grype scan with
                proc_env = self._get_proc_env()

                # Format and run the command
                cmd = "{grype_sub_command} sbom:{sbom}".format(
                    grype_sub_command=self.GRYPE_SUB_CMD, sbom=grype_sbom_file
                )

                logger.debug("Running grype with command: {}".format(cmd))

                stdout = None
                err = None
                try:
                    stdout, _ = run_check(shlex.split(cmd), env=proc_env)
                except CommandException as exc:
                    logger.error(
                        "Exception running command: {}, stderr: {}".format(
                            cmd, exc.stderr
                        )
                    )
                    raise exc
            finally:
                read_lock.release()

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
        read_lock = self._grype_db_lock.gen_rlock()
        if read_lock.acquire(blocking=False, timeout=60):
            try:
                if type(vuln_id) == str:
                    vuln_id = [vuln_id]

                if type(namespace) == str:
                    namespace = [namespace]

                logger.debug(
                    "Querying grype_db for vuln_id: {}, namespace: {}, affected_package: {}".format(
                        vuln_id, namespace, affected_package
                    )
                )

                query = self._grype_db_session.query(GrypeVulnerability).join(
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
            finally:
                read_lock.release()

    def query_record_source_counts(self):
        """
        Query the current feed group counts for all current vulnerabilities.
        """
        # Get and release read locks
        read_lock = self.grype_db_lock.gen_rlock()
        if read_lock.acquire(blocking=False, timeout=60):
            try:
                logger.debug("Querying grype_db for feed group counts")

                # Get the counts for each record source
                results = (
                    self._get_grype_db_session()
                    .query(
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

            finally:
                read_lock.release()
