import copy
from urllib.parse import quote

import pytest

from tests.functional.services.api.registries import get_registry_info
from tests.functional.services.utils.http_utils import APIResponse, http_get, http_put


class TestRegistriesAPIPutReturns200:
    @pytest.mark.skip(
        reason="Right now the Update API doesn't seem to be able to handle URL encoded registry strings well"
    )
    def test_update_registry_by_name(self, add_and_teardown_registry):
        add_resp, api_conf = add_and_teardown_registry
        get_resp = http_get(
            ["registries", quote(get_registry_info()["service_name"], "")],
            config=api_conf,
        )
        assert get_resp == APIResponse(200)

        # copy payload from existing (password isn't provided, so re-add it)
        update_payload = copy.copy(get_resp.body[0])
        update_payload["registry_name"] = "updated_registry_name_functional_test"
        update_payload["registry_pass"] = get_registry_info()["pass"]
        update_resp = http_put(
            ["registries", "docker-registry:5000"],
            payload=update_payload,
            config=api_conf,
        )
        assert update_resp == APIResponse(200)
