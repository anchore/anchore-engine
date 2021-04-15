import anchore_engine.configuration.localconfig
import os
import json
import shlex
import sqlalchemy
import uuid

from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys import logger
from anchore_engine.subsys.locking import ManyReadsOneWriteLock
from anchore_engine.utils import run_check
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from threading import Lock


grype_db_file = None
grype_db_session = None
grype_db_lock = ManyReadsOneWriteLock()
grype_db_write_lock = Lock()

Base = declarative_base()
VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"


def _get_default_cache_dir_from_config():
    """
    Get the default grype db dir from config.
    """
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if "grype_db_cache_dir" in localconfig:
        full_path = os.path.join(localconfig["service_dir"], localconfig["grype_db_cache_dir"])
    else:
        full_path = os.path.join("/tmp/anchoretmp", "grype_db/")

    if not os.path.exists(full_path):
        # TODO makedirs (plural) is probably wrong. Outside of unit tests service dir should already exist at this point.
        os.makedirs(full_path)

    return full_path


def _write_grype_db_to_file(lastest_grype_db):
    """
    Write the new grype db definition to file, and return the file
    """
    local_db_dir = _get_default_cache_dir_from_config()
    # TODO If there is a unique and identifying file name we can get or derive upstream from the db metadata
    # (ie something with the timestamp) that would be much preferable to a unique but meaningless uuid.
    uuid_file_name = str(uuid.uuid4())
    latest_grype_db_file = "{}{}".format(local_db_dir, uuid_file_name)
    # Write the passed grype db to that file
    with open(latest_grype_db_file, "w") as local_grype_db_output:
        local_grype_db_output.write(lastest_grype_db)
    return latest_grype_db_file


def _init_grype_db_engine(latest_grype_db_file):
    """
    Create and return the sqlalchemy engine object
    """
    db_connect = "sqlite:///{}".format(latest_grype_db_file)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    return latest_grype_db_engine


def _init_grype_db_session(grype_db_engine):
    """
    Create and return the db session
    """
    SessionMaker = sessionmaker(bind=grype_db_engine)
    grype_db_session = SessionMaker()
    return grype_db_session


def _init_grype_db_engine(lastest_grype_db: str):
    """
    Write the db string to file, create the engine, and create the session
    Return the file and session
    """
    latest_grype_db_file = _write_grype_db_to_file(lastest_grype_db)
    latest_grype_db_engine = _init_grype_db_engine(latest_grype_db_file)
    latest_grype_db_session = _init_grype_db_session(latest_grype_db_engine)

    # Return the engine
    return latest_grype_db_file, latest_grype_db_session


def _remove_local_grype_db(grype_db_file):
    """
    Remove the local grype db, either because we've replaced it, or it is new but not well-structured
    """
    if os.path.exists(grype_db_file):
        os.remove(grype_db_file)
    else:
        logger.error("Failed to remove grype db at {} as it cannot be found.".format(grype_db_file))
    return


def update_grype_db(lastest_grype_db):
    """
    Update the installed grype db with the provided definition, and remove the old grype db file.
    This method does not validation of the db, and assumes it has passed any required validation upstream
    """
    global grype_db_file, grype_db_session

    with grype_db_lock.write_lock():
        # Store the db locally and
        # Create the sqlalchemy engine for the new db
        latest_grype_db_file, latest_grype_db_session = _init_grype_db_engine(lastest_grype_db)

        # Store the file and session variables globally
        # For use during reads and to remove in the next update
        old_grype_db_file = grype_db_file
        grype_db_file = latest_grype_db_file
        grype_db_session = latest_grype_db_session

        # Remove the old local db
        _remove_local_grype_db(old_grype_db_file)


def get_vulnerabilities(grype_sbom: str):
    """
    Use grype to scan the provided sbom for vulnerabilites.
    """
    global grype_db_file

    # Get the read lock
    with grype_db_lock.read_access():
        # Set grype env variables, including the grype db location
        grype_env = {
            "GRYPE_CHECK_FOR_APP_UPDATE": "0",
            "GRYPE_LOG_STRUCTURED": "1",
            "GRYPE_DB_CACHE_DIR": "{}".format(grype_db_file),
        }

        proc_env = os.environ.copy()
        proc_env.update(grype_env)

        # Format and run the command
        cmd = "grype -vv -o json sbom:{sbom}".format(
            sbom=grype_sbom,
        )
        stdout, _ = run_check(shlex.split(cmd), env=proc_env)

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
    with grype_db_lock.read_access():
        if type(vuln_id) == str:
            vuln_id = [vuln_id]

        if type(namespace) == str:
            namespace = [namespace]

        query = grype_db_session.query(
            GrypeVulnerability, GrypeVulnerabilityMetadata
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
