import pytest

from tests.functional.services.api.images import get_image_digest
from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestArchivesAPIGetReturns200:
    """
    Add and removal of the archive rule is tested implicitly through the create_and_teardown_archive_rule fixture
    """

    def test_list_archives(self, create_and_teardown_archive_rule):
        image_resp, rule_resp, archive_resp, api_conf = create_and_teardown_archive_rule
        resp = http_get(["archives"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_archived_images(self, create_and_teardown_archive_rule):
        image_resp, rule_resp, archive_resp, api_conf = create_and_teardown_archive_rule
        resp = http_get(["archives", "images"], config=api_conf)
        assert resp == APIResponse(200)

    def test_get_archived_images_by_digest(self, create_and_teardown_archive_rule):
        """
        Implicitly tests adding an image to the archive and deleting it
        """
        image_resp, rule_resp, archive_resp, api_conf = create_and_teardown_archive_rule
        image_digest = get_image_digest(image_resp)
        resp = http_get(["archives", "images", image_digest], config=api_conf)
        assert resp == APIResponse(200)

    @pytest.mark.parametrize(
        "query",
        [
            pytest.param({}, id="noparam"),
            pytest.param({"system_global": True}, id="system-global=true"),
            pytest.param({"system_global": False}, id="system-global=false"),
        ],
    )
    def test_get_archive_rules(self, create_and_teardown_archive_rule, query):
        image_resp, rule_resp, archive_resp, api_conf = create_and_teardown_archive_rule
        resp = http_get(["archives", "rules"], query=query, config=api_conf)
        assert resp == APIResponse(200)

    def test_get_archive_rule_by_id(self, create_and_teardown_archive_rule):
        image_resp, rule_resp, archive_resp, api_conf = create_and_teardown_archive_rule
        resp = http_get(
            ["archives", "rules", rule_resp.body.get("rule_id")], config=api_conf
        )
        assert resp == APIResponse(200)
