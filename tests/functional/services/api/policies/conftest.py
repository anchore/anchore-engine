import json

import pytest

from tests.functional import get_logger
from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.utils.http_utils import (
    RequestFailedError,
    http_del,
    http_post,
)

_logger = get_logger(__name__)


@pytest.fixture(scope="class", params=USER_API_CONFS)
def create_policy_from_artifact_and_teardown(request, pytestconfig):
    """
    Implicitly tests ADD and DELETE operations for policies
    """

    _logger.info("Loading Policy Bundle JSON from Artifact")
    with open(
        pytestconfig.rootdir
        + "/tests/functional/artifacts/bundle-with-all-rules-2020-08-20.json"
    ) as file:
        policy_bundle_all_rules = json.load(file)

    resp = http_post(["policies"], policy_bundle_all_rules, config=request.param)
    if resp.code != 200:
        raise RequestFailedError(resp.url, resp.code, resp.body)

    policy_id = resp.body.get("policyId")

    def delete_policies():
        del_resp = http_del(["policies", policy_id], config=request.param)
        if del_resp.code != 200:
            raise RequestFailedError(del_resp.url, del_resp.code, del_resp.body)

    request.addfinalizer(delete_policies)
    return policy_bundle_all_rules, policy_id, request.param
