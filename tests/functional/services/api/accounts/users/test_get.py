import pytest

from tests.functional.services.api.conftest import (
    FT_ACCOUNT,
    USER_API_CONFS,
    get_ft_user,
)
from tests.functional.services.utils.http_utils import APIResponse, http_get


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestAccountUsersAPIGetReturns200:
    def test_list_ft_account_users(self, api_conf):
        resp = http_get(["accounts", FT_ACCOUNT, "users"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_ft_account_user_by_username(self, api_conf):
        ft_user = get_ft_user()
        get_resp = http_get(
            ["accounts", FT_ACCOUNT, "users", ft_user["username"]], config=api_conf
        )
        assert get_resp == APIResponse(200)
