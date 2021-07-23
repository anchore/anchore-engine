import pytest

from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestAccountsAPIGetReturns200:
    @pytest.mark.parametrize("state", ["disabled", "deleting"])
    def test_list_accounts(self, state):
        # TODO: Add '' param back (https://github.com/anchore/anchore-engine/issues/603)
        resp = http_get(["accounts"], query={"state": state})
        assert resp == APIResponse(200)

    def test_get_admin_account(self):
        resp = http_get(["accounts", "admin"])
        assert resp == APIResponse(200)
