import pytest

from anchore_engine.clients import localanchore_standalone
from anchore_engine.clients.localanchore_standalone import (
    AnalysisError,
    retrying_pull_image,
)
from anchore_engine.subsys import logger

logger.enable_test_logging(level="DEBUG")

fail_counter = 0
fail_threshold = 2


def always_fail(*args, **kwargs):
    global fail_counter
    fail_counter += 1
    raise AnalysisError(
        msg="", pull_string="testing", tag="latest", cause=Exception("cannot pull")
    )


def fail_twice(*args, **kwargs):
    global fail_counter, fail_threshold

    if fail_counter < fail_threshold:
        fail_counter += 1
        raise AnalysisError(
            msg="",
            pull_string="somepullstring",
            tag="latest",
            cause=Exception("cannot pull"),
        )
    else:
        return True


@pytest.fixture()
def alwaysfail_pull(monkeypatch):
    monkeypatch.setattr(localanchore_standalone, "pull_image", always_fail)


@pytest.fixture()
def fail2_pull(monkeypatch):
    monkeypatch.setattr(localanchore_standalone, "pull_image", fail_twice)


def test_retrying_image_pull_full_failure(alwaysfail_pull):
    """
    Test retry logic on image pulls. Since this is unit test, only test failure cases using mocked function

    :return:
    """

    global fail_counter
    with pytest.raises(AnalysisError):
        retrying_pull_image(
            staging_dirs={},
            pullstring="somepullstring",
            registry_creds=[],
            manifest=None,
            parent_manifest=None,
        )

    assert fail_counter == 3
    fail_counter = 0


def test_retrying_image_pull_partial_failure(fail2_pull):
    """
    Test retry logic on image pulls. Since this is unit test, only test failure cases using mocked function

    :return:
    """
    global fail_counter
    fail_counter = 0
    retrying_pull_image(
        staging_dirs={},
        pullstring="somepullstring",
        registry_creds=[],
        manifest=None,
        parent_manifest=None,
    )

    assert fail_counter == 2
    fail_counter = 0
