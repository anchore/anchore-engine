import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_post


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestRepositoriesAPIGetReturns200:
    def test_add_repository(self, api_conf):
        resp = http_post(
            ["repositories"],
            None,
            query={"repository": "docker.io/alpine"},
            config=api_conf,
        )
        assert resp == APIResponse(200)
