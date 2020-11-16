from urllib.parse import quote

import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional import get_logger
from tests.functional.services.api.registries import get_registry_info
from tests.functional.services.utils.http_utils import (
    RequestFailedError,
    http_post,
    http_del,
)

_logger = get_logger(__name__)


@pytest.fixture(scope="session", autouse=True)
def add_image_to_local_registry(docker_client):
    """
    Pull alpine:latest to local environment, and re-tag it for the local docker-registry
    Note: if the docker registry run by tests/functional/artifacts/registry/docker-registry-service.yaml is not up,
    this will fail
    """
    _logger.info("Pulling alpine:latest image from remote")
    docker_client.images.pull("alpine:latest")

    _logger.info("Re-tagging as the local docker registry's image")
    rc = docker_client.api.tag("alpine:latest", "localhost:5000/alpine", "latest")
    if not rc:
        raise RequestFailedError(rc, "docker_client:tag", None)

    # Login to the Local Registry (running from tests/functional/artifacts/registry/docker-registry-service.yaml
    registry_info = get_registry_info()
    _logger.info("Ensure we are logged into the local docker registry")
    docker_client.login(
        username=registry_info["user"],
        password=registry_info["pass"],
        registry=registry_info["host"],
    )

    _logger.info("Push the re-tagged image to the local docker registry")
    docker_client.images.push("localhost:5000/alpine", "latest")


@pytest.fixture(scope="class", params=USER_API_CONFS)
def add_and_teardown_registry(request):
    registry_info = get_registry_info()
    registry_payload = {
        "registry": registry_info["service_name"],
        "registry_name": "localhost",
        "registry_pass": registry_info["pass"],
        "registry_type": "docker_v2",
        "registry_user": registry_info["user"],
        "registry_verify": False,
    }
    _logger.info("Adding Registry. APIConf={}".format(str(request.param.__name__)))
    add_registry_resp = http_post(
        ["registries"], registry_payload, config=request.param
    )
    if add_registry_resp.code != 200:
        raise RequestFailedError(
            add_registry_resp.url, add_registry_resp.code, add_registry_resp.body
        )

    def remove_registry():
        _logger.info(
            "Removing Registry. APIConf={}".format(str(request.param.__name__))
        )
        remove_resp = http_del(
            ["registries", quote(registry_info["service_name"])], config=request.param
        )
        if remove_resp.code != 200:
            raise RequestFailedError(
                remove_resp.url,
                remove_resp.code,
                "" if not hasattr(remove_resp, "body") else remove_resp.body,
            )

    request.addfinalizer(remove_registry)
    return add_registry_resp, request.param
