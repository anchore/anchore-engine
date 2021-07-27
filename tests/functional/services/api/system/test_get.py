import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import APIResponse, http_get


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestSystemAPIGetReturns200:
    def test_service_status(self, api_conf):
        resp = http_get(["status"], config=api_conf)
        assert resp == APIResponse(200)

    def test_system_status(self, api_conf):
        resp = http_get(["system"], config=api_conf)
        assert resp == APIResponse(200)

    def test_system_error_codes(self, api_conf):
        resp = http_get(["system", "error_codes"], config=api_conf)
        assert resp == APIResponse(200)

    def test_system_feeds(self, api_conf):
        resp = http_get(["system", "feeds"], config=api_conf)
        assert resp == APIResponse(200)

    def test_system_policy_spec(self, api_conf):
        resp = http_get(["system", "policy_spec"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_system_services_endpoints(self, api_conf):
        """
        Test system services.
        NOTE! This only works for the super root user, so if the api_conf isn't that user, skip.
        Why do we even keep the api_conf in the function argument you ask? Because it's required in order to allow
        for pytest mark parametrization at the class level
        """
        api_conf_name = str(api_conf.__name__)
        if api_conf_name != "get_api_conf":
            pytest.skip(
                "System Services Endpoint only works for root user of admin account: currentUserAPIConf={}".format(
                    api_conf_name
                )
            )

        resp = http_get(["system", "services"], config=api_conf)
        assert resp == APIResponse(200)

        services = resp.body
        for service in services:
            service_name = service.get("servicename")
            resp = http_get(["system", "services", service_name], config=api_conf)
            assert resp == APIResponse(200)

            service_details = resp.body

            resp = http_get(
                ["system", "services", service_name, service_details[0].get("hostid")],
                config=api_conf,
            )
            assert resp == APIResponse(200)
