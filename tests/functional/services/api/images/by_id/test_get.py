import pytest

from tests.functional.services.api.images import (
    get_image_id,
    get_image_tag,
    wait_for_image_to_analyze,
)
from tests.functional.services.api.policies import get_first_policy_id
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestImagesByIDAPIGetReturns200:
    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"policyId": True}, id="withPolicyId"),
            pytest.param({"detail": True}, id="detail=true"),
            pytest.param({"detail": False}, id="detail=false"),
            pytest.param({"history": True}, id="history=true"),
            pytest.param({"history": False}, id="history=false"),
        ],
    )
    def test_get_image_policy_evaluation(self, add_alpine_latest_image, query):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_tag = get_image_tag(add_resp)

        query["tag"] = image_tag
        if query.get("policyId"):
            query["policyId"] = get_first_policy_id(api_conf)

        resp = http_get(
            ["images", "by_id", image_id, "check"], {"tag": image_tag}, config=api_conf
        )
        assert resp == APIResponse(200)

    def test_list_image_content_types(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        resp = http_get(["images", "by_id", image_id, "content"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_files(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        resp = http_get(
            ["images", "by_id", image_id, "content", "files"], config=api_conf
        )

        assert resp == APIResponse(200)

    def test_get_image_content_java(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        resp = http_get(
            ["images", "by_id", image_id, "content", "java"], config=api_conf
        )

        assert resp == APIResponse(200)

    def test_get_image_content_ctype(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        resp = http_get(["images", "by_id", image_id, "content", "os"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_vuln_types(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        resp = http_get(["images", "by_id", image_id, "vuln"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_all_image_vulns_by_type(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        resp = http_get(["images", "by_id", image_id, "vuln"], config=api_conf)

        assert resp == APIResponse(200)

        wait_for_image_to_analyze(image_id, api_conf)

        vuln_types = resp.body
        for v_type in vuln_types:
            resp = http_get(
                ["images", "by_id", image_id, "vuln", v_type], config=api_conf
            )
            assert resp == APIResponse(200)
