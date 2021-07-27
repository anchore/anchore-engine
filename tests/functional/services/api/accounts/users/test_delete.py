import pytest

from tests.functional.services.api.accounts.users import create_ft_account_user
from tests.functional.services.api.conftest import FT_ACCOUNT, USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_del


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestAdminUsersAPIDeleteReturns200:
    def test_delete_admin_user(self, api_conf):
        create_ft_account_user("deletion_test", "lebronForPresident", api_conf)

        delete_resp = http_del(
            ["accounts", FT_ACCOUNT, "users", "deletion_test"], config=api_conf
        )
        assert delete_resp == APIResponse(204)
