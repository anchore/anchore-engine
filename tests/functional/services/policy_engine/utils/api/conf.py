import os

from tests.functional.services.utils import http_utils

POLICY_ENGINE_API_CONF = http_utils.DEFAULT_API_CONF.copy()
POLICY_ENGINE_API_CONF["ANCHORE_BASE_URL"] = os.environ.get(
    "ANCHORE_POLICY_ENGINE_URL", "http://engine-policy-engine:8228/v1"
)


def policy_engine_api_conf():
    return POLICY_ENGINE_API_CONF
