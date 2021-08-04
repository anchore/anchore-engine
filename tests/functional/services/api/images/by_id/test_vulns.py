from tests.functional.services.api.images import get_image_id, wait_for_image_to_analyze
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestVulns:
    def test_get_image_vuln_types(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        resp = http_get(["images", "by_id", image_id, "vuln"], config=api_conf)

        # Doing it with this one I think
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

    def test_vendor_only_field_present(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)
        wait_for_image_to_analyze(image_id, api_conf)

        resp = http_get(["images", "by_id", image_id, "vuln", "all"], config=api_conf)

        assert resp == APIResponse(200)

        for vuln in resp.body["vulnerabilities"]:
            assert "will_not_fix" in vuln
