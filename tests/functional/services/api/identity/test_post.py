import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_post


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestIdentityAPIPostReturns200:
    def test_add_credential(self, api_conf):
        """
        Do an add-in-place (i.e. do not change the password as it is depended on throughout the other tests)
        """
        resp = http_post(
            ["user", "credentials"],
            {"type": "password", "value": api_conf()["ANCHORE_API_PASS"]},
            config=api_conf,
        )
        assert resp == APIResponse(200)
