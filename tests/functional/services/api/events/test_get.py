from datetime import datetime, timedelta

import pytest

from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.api.subscriptions import SUBSCRIPTION_TYPES
from tests.functional.services.utils.http_utils import APIResponse, http_get

SERVICES = [
    "analyzer",
    "api",
    "catalog",
    "simpleq",
    "policy-engine",
    "rbac-authorizer",
    "rbac-manager",
    "reports",
    "notifications",
    "feeds",
]


def get_event_id_from_list_resp(list_resp):
    return list_resp.get("results", {})[0].get("generated_uuid")


@pytest.mark.parametrize("api_conf", USER_API_CONFS)
class TestEventsAPIGetReturns200:
    def test_list_events(self, api_conf):
        resp = http_get(["events"], {"page": 1, "limit": 1}, config=api_conf)
        assert resp == APIResponse(200)

    @pytest.mark.parametrize("source", SERVICES)
    def test_list_events_with_source_servicename(self, api_conf, source):
        resp = http_get(
            ["events"],
            {"source_servicename": source, "page": 1, "limit": 1},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    def test_list_events_with_source_servicename(self, api_conf):
        resp = http_get(
            ["events"],
            {"source_hostid": "anchore-quickstart", "page": 1, "limit": 1},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    @pytest.mark.parametrize("e_type", SUBSCRIPTION_TYPES)
    def test_list_events_with_event_type(self, api_conf, e_type):
        resp = http_get(
            ["events"], {"event_type": e_type, "page": 1, "limit": 1}, config=api_conf
        )
        assert resp == APIResponse(200)

    @pytest.mark.parametrize("r_type", ["image_tag", "imageDigest", "repository"])
    def test_list_events_with_resource_type(self, api_conf, r_type):
        resp = http_get(
            ["events"],
            {"resource_type": r_type, "page": 1, "limit": 1},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    def test_list_events_with_resource_id(self, api_conf):
        resp = http_get(
            ["events"],
            {"resource_id": "docker.io/alpine:latest", "page": 1, "limit": 1},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    @pytest.mark.parametrize("level", ["INFO", "ERROR"])
    def test_list_events_with_level(self, api_conf, level):
        resp = http_get(
            ["events"], {"level": level, "page": 1, "limit": 1}, config=api_conf
        )
        assert resp == APIResponse(200)

    def test_list_events_with_since(self, api_conf):
        five_min_ago = str(datetime.now() - timedelta(minutes=5))
        resp = http_get(
            ["events"], {"since": five_min_ago, "page": 1, "limit": 1}, config=api_conf
        )
        assert resp == APIResponse(200)

    def test_list_events_with_before(self, api_conf):
        resp = http_get(
            ["events"],
            {"before": str(datetime.now()), "page": 1, "limit": 1},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    def test_list_event_types(self, api_conf):
        resp = http_get(["event_types"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_event_by_id(self, api_conf):
        resp = http_get(["events"], {"page": 1, "limit": 1}, config=api_conf)
        assert resp == APIResponse(200)

        event_id = get_event_id_from_list_resp(resp.body)
        resp = http_get(["events", event_id], config=api_conf)
        assert resp == APIResponse(200)
