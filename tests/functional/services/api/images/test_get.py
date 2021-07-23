import pytest

from tests.functional.services.api.images import (
    get_image_digest,
    get_image_id,
    get_image_tag,
    wait_for_image_to_analyze,
)
from tests.functional.services.api.policies import get_first_policy_id
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestImageAPIGetReturns200:
    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"history": True}, id="history=true"),
            pytest.param({"history": False}, id="history=false"),
            pytest.param({"fulltag": "docker.io/alpine:latest"}, id="fulltag"),
            pytest.param({"image_status": "all"}, id="image_status=all"),
            pytest.param({"image_status": "active"}, id="image_status=active"),
            pytest.param({"image_status": "deleting"}, id="image_status=deleting"),
            pytest.param(
                {"analysis_status": "not_analyzed"}, id="analysis_status=not_analyzed"
            ),
            pytest.param(
                {"analysis_status": "analyzing"}, id="analysis_status=analyzing"
            ),
            pytest.param(
                {"analysis_status": "analysis_failed"},
                id="analysis_status=analysis_failed",
            ),
        ],
    )
    def test_list_image(self, add_alpine_latest_image, query):
        """
        Atomically test list image functionality with add and teardown (by_id) implicit coverage
        """
        add_resp, api_conf = add_alpine_latest_image
        resp = http_get(["images"], query=query, config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_metadata(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest], config=api_conf)

        assert resp == APIResponse(200)

    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"policyId": True}, id="withPolicyId"),
            pytest.param({"detail": True}, id="detail=true"),
            pytest.param({"detail": False}, id="detail=false"),
            pytest.param({"history": True}, id="history=true"),
            pytest.param({"history": False}, id="history=false"),
            pytest.param({"interactive": True}, id="interactive=true"),
            pytest.param({"interactive": False}, id="interactive=false"),
        ],
    )
    def test_get_image_policy_eval(self, add_alpine_latest_image, query):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)
        image_tag = get_image_tag(add_resp)

        query["tag"] = image_tag
        if query.get("policyId"):
            query["policyId"] = get_first_policy_id(api_conf)

        resp = http_get(["images", image_digest, "check"], query=query, config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_types_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "content"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_files_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "content", "files"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_java_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "content", "java"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_malware_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "content", "malware"], config=api_conf)

        assert resp == APIResponse(200)

    def test_get_image_content_all_types_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "content"], config=api_conf)

        assert resp == APIResponse(200)

        c_types = resp.body
        for c_type in c_types:
            resp = http_get(
                ["images", image_digest, "content", c_type], config=api_conf
            )
            assert resp == APIResponse(200)

    def test_get_image_metadata_all_types_by_digest(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "metadata"], config=api_conf)

        assert resp == APIResponse(200)

        m_types = resp.body
        for m_type in m_types:
            resp = http_get(
                ["images", image_digest, "metadata", m_type], config=api_conf
            )
            assert resp == APIResponse(200)

    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"force_refresh": True}, id="force_refresh=true"),
            pytest.param({"force_refresh": False}, id="force_refresh=false"),
            pytest.param({"vendor_only": True}, id="vendor_only=true"),
            pytest.param({"vendor_only": False}, id="vendor_only=false"),
        ],
    )
    def test_get_image_vulns_all_types_by_digest(self, add_alpine_latest_image, query):
        add_resp, api_conf = add_alpine_latest_image
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "vuln"], config=api_conf)

        assert resp == APIResponse(200)

        v_types = resp.body
        for v_type in v_types:
            resp = http_get(
                ["images", image_digest, "vuln", v_type], query=query, config=api_conf
            )
            assert resp == APIResponse(200)

    def test_get_image_file_content_artifacts(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image

        api_conf_name = str(api_conf.__name__)
        if api_conf_name != "get_api_conf":
            pytest.skip(
                "Image File Content Search Endpoint only works for root user of admin account: currentUserAPIConf={}".format(
                    api_conf_name
                )
            )
        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "artifacts", "file_content_search"])
        assert resp == APIResponse(200)

    def test_get_image_retrieved_files(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image

        api_conf_name = str(api_conf.__name__)
        if api_conf_name != "get_api_conf":
            pytest.skip(
                "Image Retrieved Files Endpoint only works for root user of admin account: currentUserAPIConf={}".format(
                    api_conf_name
                )
            )

        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "artifacts", "retrieved_files"])
        assert resp == APIResponse(200)

    def test_get_image_secret_search(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image

        api_conf_name = str(api_conf.__name__)
        if api_conf_name != "get_api_conf":
            pytest.skip(
                "Image Secret Search Endpoint only works for root user of admin account: currentUserAPIConf={}".format(
                    api_conf_name
                )
            )

        image_id = get_image_id(add_resp)

        wait_for_image_to_analyze(image_id, api_conf)

        image_digest = get_image_digest(add_resp)

        resp = http_get(["images", image_digest, "artifacts", "secret_search"])
        assert resp == APIResponse(200)
