import os

from tests.functional.services.utils import http_utils

CATALOG_API_CONF = http_utils.DEFAULT_API_CONF.copy()
CATALOG_API_CONF["ANCHORE_BASE_URL"] = os.environ.get(
    "ANCHORE_CATALOG_URL", "http://engine-catalog:8228/v1"
)


def catalog_api_conf():
    return CATALOG_API_CONF
