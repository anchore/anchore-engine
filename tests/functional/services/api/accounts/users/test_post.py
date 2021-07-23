import pytest

from tests.functional.services.api.accounts.users import delete_ft_account_user
from tests.functional.services.api.conftest import FT_ACCOUNT, USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_post


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestAdminUsersAPIPostReturns200:
    def test_add_user(self, api_conf):
        create_resp = http_post(
            ["accounts", FT_ACCOUNT, "users"],
            {"username": "creation_test", "password": "lebronForPresident"},
            config=api_conf,
        )
        assert create_resp == APIResponse(200)
        delete_ft_account_user("creation_test", api_conf)
