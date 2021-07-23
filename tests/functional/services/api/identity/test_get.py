import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_get


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestIdentityAPIGetReturns200:
    def test_list_user_account(self, api_conf):
        resp = http_get(["account"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_user_info(self, api_conf):
        resp = http_get(["user"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_user_credential_summary(self, api_conf):
        resp = http_get(["user", "credentials"], config=api_conf)
        assert resp == APIResponse(200)
