from urllib.parse import quote

from tests.functional.services.api.registries import get_registry_info
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestRegistriesAPIGetReturns200:
    def test_list_registries(self, add_and_teardown_registry):
        add_resp, api_conf = add_and_teardown_registry
        resp = http_get(["registries"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_registry_by_name(self, add_and_teardown_registry):
        add_resp, api_conf = add_and_teardown_registry
        resp = http_get(
            ["registries", quote(get_registry_info()["service_name"], "")],
            config=api_conf,
        )
        assert resp == APIResponse(200)
