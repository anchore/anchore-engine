import os
import json
import shlex

from anchore_engine.utils import run_check
from enum import Enum


class GrypeImageScheme(Enum):
    DOCKER = "docker"
    DOCKER_ARCHIVE = "docker-archive"
    OCI_ARCHIVE = "oci-archive"
    OCI_DIR = "oci-dir"
    DIR = "dir"
    SBOM = "sbom"


def run_grype(image: str, image_scheme: GrypeImageScheme):
    proc_env = os.environ.copy()

    # TODO Replace this with a call to get this value, presumably from the config
    grype_db_cache_location = ""

    grype_env = {
        "GRYPE_CHECK_FOR_APP_UPDATE": "0",
        "GRYPE_LOG_STRUCTURED": "1",
        "GRYPE_DB_CACHE_DIR": "{}".format(grype_db_cache_location),
    }

    proc_env.update(grype_env)

    cmd = "grype -vv -o json {image_scheme}:{image}".format(
        image_scheme=image_scheme.value,
        image=image,
    )

    stdout, _ = run_check(shlex.split(cmd), env=proc_env)

    return json.loads(stdout)


def init_grype_db():
    # TODO Initialize the grype-db cache, or update it if it already exists
    pass


def query_vulnerabilities(
        vuln_id=None,
        affected_package=None,
        affected_package_version=None,
        namespace=None,
):
    if vuln_id and type(vuln_id) == list:
        vuln_id = ",".join(vuln_id)

    if namespace and type(namespace) == list:
        namespace = ",".join(namespace)

    # TODO Query the grype-db cache for vulnerabilities using the passed params and return
    pass
