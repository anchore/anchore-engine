import anchore_engine.configuration.localconfig
import os
import json
import shlex
import sqlalchemy

from anchore_engine.db.entities.common import UtilMixin
from anchore_engine.subsys import logger
from anchore_engine.utils import run_check
from enum import Enum
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


grype_db_session = None
Base = declarative_base()
VULNERABILITY_TABLE_NAME = "vulnerability"
VULNERABILITY_METADATA_TABLE_NAME = "vulnerability_metadata"


class GrypeImageScheme(Enum):
    DOCKER = "docker"
    DOCKER_ARCHIVE = "docker-archive"
    OCI_ARCHIVE = "oci-archive"
    OCI_DIR = "oci-dir"
    DIR = "dir"
    SBOM = "sbom"


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


def _get_cache_location_from_config():
    localconfig = anchore_engine.configuration.localconfig.get_config()
    return localconfig.get("grype_db_cache_location", None)


def run_grype(image: str, image_scheme: GrypeImageScheme):
    grype_env = {
        "GRYPE_CHECK_FOR_APP_UPDATE": "0",
        "GRYPE_LOG_STRUCTURED": "1",
        "GRYPE_DB_CACHE_DIR": "{}".format(_get_cache_location_from_config()),
    }

    proc_env = os.environ.copy()
    proc_env.update(grype_env)

    cmd = "grype -vv -o json {image_scheme}:{image}".format(
        image_scheme=image_scheme.value,
        image=image,
    )

    stdout, _ = run_check(shlex.split(cmd), env=proc_env)

    return json.loads(stdout)


def init_grype_db_session(retry=True):
    global grype_db_session

    # Pull the cache location from the config
    db_connect = "sqlite:///{}".format(_get_cache_location_from_config())
    engine = sqlalchemy.create_engine(db_connect, echo=True)

    # Ensure that the grype-db instance has the tables we are looking for
    # If not, try at least once to reinitialize the cache
    # TODO This needs more attention
    if not engine.has_table(VULNERABILITY_TABLE_NAME) or not engine.has_table(VULNERABILITY_METADATA_TABLE_NAME):
        if retry:
            logger.error("grype-db tables not found. Retrying.".format(VULNERABILITY_TABLE_NAME))
            init_grype_db()
            init_grype_db_session(retry=False)
        else:
            logger.error("grype-db tables not found. grype-db client has not been initialized".format(VULNERABILITY_TABLE_NAME))
            # TODO Need to throw an exception here, at least, and better understand where this could be run from
            # Ie what needs to fail, what needs to block, what needs to retry, etc. if this cache is not present
            return

    # Create the db session
    SessionMaker = sessionmaker(bind=engine)
    grype_db_session = SessionMaker()


def init_grype_db():
    # TODO Initialize the grype-db cache, or update it if it already exists
    pass


def query_vulnerabilities(
        vuln_id=None,
        affected_package=None,
        affected_package_version=None,
        namespace=None,
):
    if grype_db_session is None:
        init_grype_db_session()

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
        # TODO Apply package version filtering
        # It is quite a bit more complicated than this, currently
        # if affected_package_version is not None:
        #     query = query.filter(
        #         GrypeVulnerability.version_constraint == affected_package_version
        #     )

    # TODO Query will need to be updated to return data that minimizes the downstream transformation cost
    return query.all()
