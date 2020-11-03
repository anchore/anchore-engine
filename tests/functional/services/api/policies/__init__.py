from tests.functional.services.utils.http_utils import http_get


def get_first_policy_id(api_conf: callable):
    resp = http_get(["policies"], config=api_conf)
    return resp.body[0].get("policyId")
