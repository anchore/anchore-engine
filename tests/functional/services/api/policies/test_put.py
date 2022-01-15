from tests.functional.services.utils.http_utils import APIResponse, http_get, http_put


class TestPolicyAPIPutReturns200:
    def test_update_policy_by_id(self, create_policy_from_artifact_and_teardown):
        """
        Just gonna do a simple update (name change) here
        """
        policy_bundle, policy_id, api_conf = create_policy_from_artifact_and_teardown
        resp = http_get(["policies", policy_id], config=api_conf)
        policy_json = resp.body[0]
        policy_json["name"] = "UpdatedName"
        resp = http_put(["policies", policy_id], policy_json, config=api_conf)
        assert resp == APIResponse(200)
