from tests.functional import get_logger
from tests.functional.services.api.images import (
    get_alpine_latest_image_os_content,
    get_alpine_latest_image_os_vuln,
    get_image_digest,
    get_image_id,
)
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestQueryAPIGetReturns200:
    _logger = get_logger(__name__)

    def test_query_image_by_content(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        # Arbitrarily get the first package from the os content response
        first_package = (
            get_alpine_latest_image_os_content(
                get_image_id(add_resp), get_image_digest(add_resp), api_conf
            )
            .body.get("content", [])[0]
            .get("package", None)
        )

        assert first_package is not None
        resp = http_get(
            ["query", "images", "by_package"], {"name": first_package}, config=api_conf
        )
        assert resp == APIResponse(200)

    def test_query_image_by_vuln(self, add_alpine_latest_image):
        """
        These tests seem to always return early because the system needs to be up and running for a while to gather
        feed data and analyze images. Good candidates for moving to an external test suite where an environment has
        been running for a while.
        """
        add_resp, api_conf = add_alpine_latest_image
        # Arbitrarily get the first vuln from the os vuln response
        try:
            first_vuln = (
                get_alpine_latest_image_os_vuln(
                    get_image_id(add_resp), get_image_digest(add_resp), api_conf
                )
                .body.get("vulnerabilities", [])[0]
                .get("vuln", None)
            )
        except IndexError:
            self._logger.warning(
                "No vulnerabilities found, cannot test query images by vulnerabilities"
            )
            return

        assert first_vuln is not None
        resp = http_get(
            ["query", "images", "by_vulnerability"],
            {"vulnerability_id": first_vuln},
            config=api_conf,
        )
        assert resp == APIResponse(200)

    def test_query_vuln(self, add_alpine_latest_image):
        add_resp, api_conf = add_alpine_latest_image
        # Arbitrarily get the first vuln from the os vuln response for alpine image
        try:
            first_vuln = (
                get_alpine_latest_image_os_vuln(
                    get_image_id(add_resp), get_image_digest(add_resp), api_conf
                )
                .body.get("vulnerabilities", [])[0]
                .get("vuln", None)
            )
        except IndexError:
            self._logger.warning(
                "No vulnerabilities found, cannot test query vulnerabilities"
            )
            return

        assert first_vuln is not None
        resp = http_get(
            ["query", "vulnerabilities"], {"id": first_vuln}, config=api_conf
        )
        assert resp == APIResponse(200)
