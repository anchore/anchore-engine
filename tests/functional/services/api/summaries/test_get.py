import pytest

from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestSummariesAPIGetReturns200:
    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparams"),
            pytest.param({"image_status": "active"}, id="image_status=active"),
            pytest.param({"image_status": "all"}, id="image_status=all"),
            pytest.param({"image_status": "deleting"}, id="image_status=deleting"),
        ],
    )
    def test_get_image_summaries(self, add_alpine_latest_image, query):
        add_resp, api_conf = add_alpine_latest_image
        resp = http_get(["summaries", "imagetags"], query=query, config=api_conf)
        assert resp == APIResponse(200)
