import pytest

from tests.functional import get_logger
from tests.functional.services.api.conftest import USER_API_CONFS
from tests.functional.services.api.images import (
    wait_for_image_to_analyze,
    get_image_id,
    get_image_digest,
)
from tests.functional.services.utils.http_utils import (
    http_post,
    RequestFailedError,
    http_del,
)

_logger = get_logger(__name__)


@pytest.fixture(scope="class", params=[USER_API_CONFS[0]])
def create_and_teardown_archive_rule(request):
    """
    In order to interact with the archives API, a rule must be added first,
    which depends on there being an image added as well:
    1. Add node:latest image (this isn't currently depended upon in other tests)
    2. Add Archive Rule

    Note: This appears to only work for the root user ATM, so don't run w/ ft_user
    """
    _logger.info("Adding alpine:edge Image for analysis")
    add_image_resp = http_post(["images"], {"tag": "alpine:edge"}, config=request.param)
    if add_image_resp.code != 200:
        raise RequestFailedError(
            add_image_resp.url, add_image_resp.code, add_image_resp.body
        )

    wait_for_image_to_analyze(get_image_id(add_image_resp), request.param)

    archive_rule_json = {
        "analysis_age_days": 0,
        "created_at": "2020-08-25T17:15:16.865Z",
        "last_updated": "2020-08-25T17:15:16.865Z",
        "selector": {"registry": "docker.io", "repository": "alpine", "tag": "edge"},
        "system_global": True,
        "tag_versions_newer": 0,
        "transition": "archive",
    }
    _logger.info("Adding Archive Rule")
    archive_rule_resp = http_post(
        ["archives", "rules"], archive_rule_json, config=request.param
    )
    if archive_rule_resp.code != 200:
        raise RequestFailedError(
            archive_rule_resp.url, archive_rule_resp.code, archive_rule_resp.body
        )

    archive_resp = http_post(
        ["archives", "images"], [get_image_digest(add_image_resp)], config=request.param
    )
    if archive_resp.code != 200:
        raise RequestFailedError(archive_resp.url, archive_resp.code, archive_resp.body)

    def teardown():
        _logger.info("Removing alpine:edge image from anchore")
        remove_image_resp = http_del(
            ["images", "by_id", get_image_id(add_image_resp)], query={"force": True}
        )
        if remove_image_resp.code != 200:
            raise RequestFailedError(
                remove_image_resp.url, remove_image_resp.code, remove_image_resp.body
            )

        _logger.info(
            "Removing Archive Rule: rule_id={}".format(
                archive_rule_resp.body["rule_id"]
            )
        )
        remove_rule_resp = http_del(
            ["archives", "rules", archive_rule_resp.body["rule_id"]]
        )
        if remove_rule_resp.code != 200:
            raise RequestFailedError(
                remove_rule_resp.url, remove_rule_resp.code, remove_rule_resp.body
            )

        delete_archive_image_resp = http_del(
            ["archives", "images", get_image_digest(add_image_resp)],
            config=request.param,
        )
        if delete_archive_image_resp.code != 200:
            raise RequestFailedError(
                delete_archive_image_resp.url,
                delete_archive_image_resp.code,
                delete_archive_image_resp.body,
            )

    request.addfinalizer(teardown)

    return add_image_resp, archive_rule_resp, archive_resp, request.param
