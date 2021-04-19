import anchore_engine.configuration.localconfig
import os
import json
import shlex
import sqlalchemy
import tarfile

from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys import logger
from anchore_engine.utils import run_check, CommandException
from readerwriterlock import rwlock
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


grype_db_dir = None
grype_db_file = None
grype_db_session = None
grype_db_lock = rwlock.RWLockWrite()

Base = declarative_base()
VULNERABILITY_FILE_NAME = "vulnerability.db"
VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"


# TODO Implement, once added to Grype
def get_current_grype_db_checksum():
    """
    Return the checksum for the in-use version of grype db
    """
    grype_db_checksum = None
    logger.info("Returning current grype_db checksum: {}".format(grype_db_checksum))
    return grype_db_checksum


def _get_default_grype_db_dir_from_config():
    """
    Get the default grype db dir from config, and create it if it does not exist.
    """
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if "grype_db_dir" in localconfig:
        grype_db_dir = os.path.join(localconfig["service_dir"], localconfig["grype_db_dir"])
    else:
        grype_db_dir = os.path.join(localconfig["service_dir"], "grype_db/")

    if not os.path.exists(grype_db_dir):
        os.mkdir(grype_db_dir)

    return grype_db_dir


def _move_grype_db_archive(grype_db_archive_local_file_location: str, output_dir: str) -> str:
    # Get the location to move the archive to
    archive_file_name = os.path.basename(grype_db_archive_local_file_location)
    grype_db_archive_copied_file_location = os.path.join(output_dir, archive_file_name)

    # Move the archive file
    logger.info("Moving the grype_db archive from {} to {}".format(grype_db_archive_local_file_location,
                                                                   grype_db_archive_copied_file_location))
    os.replace(grype_db_archive_local_file_location, grype_db_archive_copied_file_location)
    return grype_db_archive_copied_file_location


def _open_grype_db_archive(grype_db_archive_copied_file_location: str, output_dir: str) -> str:
    logger.info("Unpacking the grype_db archive at {} into {}".format(grype_db_archive_copied_file_location, output_dir))

    # Put the extracted files in the same dir as the archive
    with tarfile.open(grype_db_archive_copied_file_location) as read_archive:
        read_archive.extractall(output_dir)


    # Return the full path to the vulnerability file
    output_path = os.path.join(output_dir, VULNERABILITY_FILE_NAME)
    logger.info("Returning the unpacked grype_db file at {}".format(output_path))
    return output_path


def _remove_grype_db_archive(grype_db_archive_local_file_location: str):
    logger.info("Removing the now-unpacked grype_db archive at {}".format(grype_db_archive_local_file_location))
    os.remove(grype_db_archive_local_file_location)


def _move_and_open_grype_db_archive(grype_db_archive_local_file_location: str) -> str:
    """
    This function moves a tarball containing the latest grype db from a location on the local file system
    into the configured grype db dir. It then extracts all files in the tarball and removes the then-unneeded
    archive file.
    """
    # Get the location to copy the archive to
    local_db_dir = _get_default_grype_db_dir_from_config()

    # Copy the archive
    grype_db_archive_copied_file_location = _move_grype_db_archive(grype_db_archive_local_file_location, local_db_dir)

    # Unpack the archive
    latest_grype_db_file = _open_grype_db_archive(grype_db_archive_copied_file_location, local_db_dir)

    # Remove the unpacked archive
    _remove_grype_db_archive(grype_db_archive_copied_file_location)

    # Return the full path to the grype db file
    return local_db_dir, latest_grype_db_file


def _init_grype_db_engine(latest_grype_db_file):
    """
    Create and return the sqlalchemy engine object
    """
    logger.info("Creating new db engine based on the grype_db at {}".format(latest_grype_db_file))
    db_connect = "sqlite:///{}".format(latest_grype_db_file)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    return latest_grype_db_engine


def _init_grype_db_session(grype_db_engine):
    """
    Create and return the db session
    """
    logger.info("Creating new db session from engine based on the grype_db at {}".format(grype_db_engine.url))
    SessionMaker = sessionmaker(bind=grype_db_engine)
    grype_db_session = SessionMaker()
    return grype_db_session


def _init_grype_db(lastest_grype_db_archive: str):
    """
    Write the db string to file, create the engine, and create the session
    Return the file and session
    """
    # TODO Further refine this, we should be extracting everything to a subdir, and letting the
    # replacement logic operate at that level (ie always write and remove the contents of an
    # archive file to a subdir under '<service-dir>/grype_db/', rather than operating on
    # the specific vulnerability.db file.
    # It sounds like we will also be getting the metata.json file, and the further contents
    # of those archives could change if they needed to.
    latest_grype_db_dir, latest_grype_db_file = _move_and_open_grype_db_archive(lastest_grype_db_archive)
    latest_grype_db_engine = _init_grype_db_engine(latest_grype_db_file)
    latest_grype_db_session = _init_grype_db_session(latest_grype_db_engine)

    # Return the dir, file, and engine
    return latest_grype_db_dir, latest_grype_db_file, latest_grype_db_session


def _remove_local_grype_db(grype_db_file):
    """
    Remove old the local grype db file
    """
    if os.path.exists(grype_db_file):
        logger.info("Removing old grype_db at {}".format(grype_db_file))
        os.remove(grype_db_file)
    else:
        logger.error("Failed to remove grype db at {} as it cannot be found.".format(grype_db_file))
    return


def update_grype_db(grype_db_archive_local_file_location:str):
    """
    Update the installed grype db with the provided definition, and remove the old grype db file.
    This method does not validation of the db, and assumes it has passed any required validation upstream
    """
    global grype_db_dir, grype_db_file, grype_db_session

    logger.info("Updating grype with a new grype_db archive from {}".format(grype_db_archive_local_file_location))

    write_lock = grype_db_lock.gen_wlock()
    if write_lock.acquire(blocking=True, timeout=60):
        try:

            # Store the db locally and
            # Create the sqlalchemy engine for the new db
            latest_grype_db_dir, latest_grype_db_file, latest_grype_db_session = _init_grype_db(grype_db_archive_local_file_location)

            # Store the dir, file, and session variables globally
            # For use during reads and to remove in the next update
            grype_db_dir = latest_grype_db_dir
            old_grype_db_file = grype_db_file
            grype_db_file = latest_grype_db_file
            grype_db_session = latest_grype_db_session

            # Remove the old local db
            _remove_local_grype_db(old_grype_db_file)
        finally:
            write_lock.release()



def get_vulnerabilities(grype_sbom: str) -> json:
    """
    Use grype to scan the provided sbom for vulnerabilites.
    """
    global grype_db_dir

    # Get the read lock
    read_lock = grype_db_lock.gen_rlock()
    if read_lock.acquire(blocking=False, timeout=60):
        try:
            # Set grype env variables, including the grype db location
            grype_env = {
                "GRYPE_CHECK_FOR_APP_UPDATE": "0",
                "GRYPE_LOG_STRUCTURED": "1",
                "GRYPE_DB_AUTO_UPDATE": "0",
                "GRYPE_DB_CACHE_DIR": "{}".format(grype_db_dir),
            }

            proc_env = os.environ.copy()
            proc_env.update(grype_env)

            # Format and run the command
            cmd = "grype -vv -o json sbom:{sbom}".format(
                sbom=grype_sbom,
            )

            logger.debug("Running grype with command: {}".format(cmd))

            stdout = None
            err = None
            try:
                stdout, _ = run_check(shlex.split(cmd), env=proc_env)
            except CommandException as exc:
                logger.error("Exception running command: {}, stderr: {}".format(cmd, exc.stderr))
                raise exc
        finally:
            read_lock.release()


        # Return the output as json
        return json.loads(stdout)




# Table definitions.
# TODO Remove these if we end up using the query API instead of the ORM api
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


class GrypeVulnerabilityMetadata(Base, UtilMixin):
    __tablename__ = VULNERABILITY_METADATA_TABLE_NAME

    id = Column(String, primary_key=True)
    record_source= Column(String)
    severity= Column(String)
    links= Column(String)
    description= Column(String)
    cvss_v2= Column(String)
    cvss_v3= Column(String)


def query_vulnerabilities(
        vuln_id=None,
        affected_package=None,
        affected_package_version=None,
        namespace=None,
):
    """
    Query the grype db for vulnerabilites. affected_package_version is unused, but is left in place for now to match the
    header of the existing function this is meant to replace.
    """
    global grype_db_session

    # Get and release read locks
    read_lock = grype_db_lock.gen_rlock()
    if read_lock.acquire(blocking=False, timeout=60):
        try:
            if type(vuln_id) == str:
                vuln_id = [vuln_id]

            if type(namespace) == str:
                namespace = [namespace]

            logger.debug("Querying grype_db for vuln_id: {}, namespace: {}, affected_package: {}".format(vuln_id, namespace, affected_package))

            query = grype_db_session.query(
                GrypeVulnerability, GrypeVulnerabilityMetadata
            # TODO Join on id explicitly between the two tables
            ).filter(
                GrypeVulnerability.id == GrypeVulnerabilityMetadata.id
            )

            if vuln_id is not None:
                query = query.filter(
                    GrypeVulnerability.id.in_(vuln_id)
                )
            if namespace is not None:
                query = query.filter(
                    GrypeVulnerability.namespace.in_(namespace)
                )
            if affected_package is not None:
                query = query.filter(
                    GrypeVulnerability.package_name == affected_package
                )

            # TODO Query may/will need to be updated to return data that minimizes the downstream transformation cost
            # The current return object data structure takes a kitchen sink approach, returning everything, and
            # could be streamlined and/or optimized
            return query.all()
        finally:
            read_lock.release()
