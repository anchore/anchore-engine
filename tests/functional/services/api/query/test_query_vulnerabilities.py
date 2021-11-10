from tests.functional import get_logger
from tests.functional.services.api.images import (
    get_alpine_latest_image_os_vuln,
    get_image_digest,
    get_image_id,
)
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestQueryVulnerabilities:
    _logger = get_logger(__name__)

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

        for vuln in resp.body["vulnerabilities"]:
            assert len(vuln["nvd_data"]) > 0

            for package in vuln["affected_packages"]:
                assert "will_not_fix" in package
                assert isinstance(package["will_not_fix"], bool) is True
