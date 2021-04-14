import anchore_engine.configuration.localconfig
import os
import json
import shlex
import sqlalchemy
import uuid

from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys.locking import ManyReadOneWriteLock
from anchore_engine.utils import run_check
from enum import Enum
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


grype_db_file = None
grype_db_session = None
grype_db_lock = ManyReadOneWriteLock()

Base = declarative_base()
VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"


# TODO Dummy stub function, implement
def _get_latest_grype_db_metadata():
    # Return the latest grype db version and a catalog link to get it
    return None, None


# TODO Dummy stub function, implement
def _get_local_grype_db_version():
    # Return the local grype db version
    return None


def _get_default_cache_dir_from_config():
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if "grype_db_cache_dir" in localconfig:
        return localconfig["grype_db_cache_dir"]
    else:
        return "grype_db/"


# TODO Dummy stub function, implement
def _get_lastest_grype_db_from_catalog(catalog_url):
    # Get the latest grype db from catalog, using the provided url, and return it
    return None


def _init_grype_db_engine(lastest_grype_db: str):
    # Get the file location for the new local grype db file
    local_db_dir = _get_default_cache_dir_from_config()
    # TODO If there is a unique file name we can get for each db version when we get it, tht would be preferable
    uuid_file_name = str(uuid.uuid4())
    latest_grype_db_file = "{}{}".format(local_db_dir, uuid_file_name)

    # Write the passed grype db to that file
    with open(latest_grype_db_file, "w") as local_grype_db_output:
        local_grype_db_output.write(lastest_grype_db)

    # Create the sqlalchemy engine object
    db_connect = "sqlite:///{}{}".format(local_grype_db_output)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)

    # Return the engine
    return latest_grype_db_file, latest_grype_db_engine


def _validate_grype_db(engine) -> bool:
    return engine.has_table(VULNERABILITY_TABLE_NAME) and engine.has_table(VULNERABILITY_METADATA_TABLE_NAME)


def _init_grype_db_session(grype_db_engine):
    # Create the db session
    SessionMaker = sessionmaker(bind=grype_db_engine)
    grype_db_session = SessionMaker()
    return grype_db_session


# TODO Dummy stub function, implement
def remove_local_grype_db():
    # Remove the local grype db, either because we've replaced it, or it is new but not well-structured
    return


def update_grype_db():
    global grype_db_file, grype_db_session

    # Get latest db version and catalog url
    latest_db_version, catalog_url = _get_latest_grype_db_metadata()

    # Get grype_db_read_lock
    release_lock_function = grype_db_lock.acquire_read_lock()
    try:
        # Get local db version
        local_db_version = _get_local_grype_db_version()
        if local_db_version != latest_db_version:
            # Release the read lock, and get the write lock
            release_lock_function()
            release_lock_function = grype_db_lock.acquire_write_lock()

            # Get the new db from catalog
            lastest_grype_db = _get_lastest_grype_db_from_catalog()

            # Store the db locally and
            # Create the sqlalchemy engine for the new db
            local_grype_db_file, latest_grype_db_engine = _init_grype_db_engine(lastest_grype_db)

            # Validate the new db
            # TODO If this fails we should delete the new db, log this, and continue with the old db
            if _validate_grype_db(latest_grype_db_engine):
                latest_grype_db_session = _init_grype_db_session(latest_grype_db_engine)

                # Remove the old local db
                remove_local_grype_db(grype_db_file)
                grype_db_file = local_grype_db_file

                grype_db_session = latest_grype_db_session

    finally:
        # Release the currently-held lock
        release_lock_function()


class GrypeImageScheme(Enum):
    DOCKER = "docker"
    DOCKER_ARCHIVE = "docker-archive"
    OCI_ARCHIVE = "oci-archive"
    OCI_DIR = "oci-dir"
    DIR = "dir"
    SBOM = "sbom"


def get_vulnerabilities(image):
    # TODO Get the sbom from the db
    grype_sbom = None
    return run_grype(grype_sbom, GrypeImageScheme.SBOM)


def run_grype(image: str, image_scheme: GrypeImageScheme):
    global grype_db_file

    # Update the grype db, if an update is available
    update_grype_db()

    # Get the read lock
    release_lock_function = grype_db_lock.acquire_read_lock()
    try:
        # Apply env variable, including the grype db location
        grype_env = {
            "GRYPE_CHECK_FOR_APP_UPDATE": "0",
            "GRYPE_LOG_STRUCTURED": "1",
            "GRYPE_DB_CACHE_DIR": "{}".format(grype_db_file),
        }

        proc_env = os.environ.copy()
        proc_env.update(grype_env)

        # Format and run the command
        cmd = "grype -vv -o json {image_scheme}:{image}".format(
            image_scheme=image_scheme.value,
            image=image,
        )
        stdout, _ = run_check(shlex.split(cmd), env=proc_env)

        return json.loads(stdout)

    finally:
        # Release the read lock
        release_lock_function()


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
    global grype_db_session

    # Update the grype db, if an update is available
    update_grype_db()

    # Get and release read locks
    release_lock_function = grype_db_lock.acquire_read_lock()

    try:
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
        # The current return object data structure is sort of a kitchen sink approach and could be tidied up
        return query.all()

    finally:
        # Release the read lock
        release_lock_function()
