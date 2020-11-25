import pytest

from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestPolicyAPIGetReturns200:
    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"detail": True}, id="detail=true"),
            pytest.param({"detail": False}, id="detail=false"),
        ],
    )
    def test_list_policies(self, create_policy_from_artifact_and_teardown, query):
        policy_bundle, policy_id, api_conf = create_policy_from_artifact_and_teardown
        resp = http_get(["policies"], query=query, config=api_conf)
        assert resp == APIResponse(200)

    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"detail": True}, id="detail=true"),
            pytest.param({"detail": False}, id="detail=false"),
        ],
    )
    def test_get_policy_by_id(self, create_policy_from_artifact_and_teardown, query):
        policy_bundle, policy_id, api_conf = create_policy_from_artifact_and_teardown
        resp = http_get(["policies", policy_id], query=query, config=api_conf)
        assert resp == APIResponse(200)
