import pytest

from anchore_engine.subsys.events.util import (
    fulltag_from_detail,
    analysis_complete_notification_factory,
)
from anchore_engine.subsys.taskstate import complete_state, base_state


ACCOUNT = "test"
IMAGE_DIGEST = "sha256:e4ca2ed0202e76be184e75fb26d14bf974193579039d5573fb2348664deef76e"
REGISTRY = "docker.io"
REPO = "centos"
TAG = "7"
DIGEST = "sha256:e4ca2ed0202e76be184e75fb26d14bf974193579039d5573fb2348664deef76e"
IMAGE_ID = "8652b9f0cb4c0599575e5a003f5906876e10c1ceb2ab9fe1786712dac14a50cf"
EXPECTED_EVENT_TYPE = "user.image.analysis.completed"


@pytest.fixture
def test_image_detail():
    return {
        "userId": ACCOUNT,
        "imageDigest": IMAGE_DIGEST,
        "registry": REGISTRY,
        "repo": REPO,
        "tag": TAG,
        "digest": DIGEST,
        "imageId": IMAGE_ID,
    }


def mock_fulltag(registry: str, repo: str, tag: str):
    return registry + "/" + repo + ":" + tag


def test_fulltag_from_detail(test_image_detail):
    # Setup expected output
    expected_output = mock_fulltag(
        test_image_detail["registry"],
        test_image_detail["repo"],
        test_image_detail["tag"],
    )

    # Function under test
    result = fulltag_from_detail(test_image_detail)

    # Assert expected results
    assert result == expected_output


def test_analysis_complete_notification_factory():
    fulltag = mock_fulltag(REGISTRY, REPO, TAG)

    # Function under test
    result = analysis_complete_notification_factory(
        ACCOUNT,
        IMAGE_DIGEST,
        base_state("analyze"),
        complete_state("analyze"),
        fulltag,
        {},
    )

    # Assert expected results
    assert result.user_id == ACCOUNT
    assert result.details["curr_eval"]["analysis_status"] == complete_state("analyze")
    assert result.details["curr_eval"]["imageDigest"] == IMAGE_DIGEST
    assert result.details["last_eval"]["analysis_status"] == base_state("analyze")
    assert result.details["last_eval"]["imageDigest"] == IMAGE_DIGEST
    assert result.resource_id == mock_fulltag(REGISTRY, REPO, TAG)
    assert result.fq_event_type() == EXPECTED_EVENT_TYPE
