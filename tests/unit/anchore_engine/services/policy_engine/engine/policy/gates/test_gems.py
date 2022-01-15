from unittest.mock import Mock

import pytest

from anchore_engine.db.entities.policy_engine import GemMetadata, Image, ImagePackage
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import gems

image_id = "1"
user = "admin"


def gem_metadata():
    return [
        GemMetadata(
            id="1",
            name="rails",
            latest="6.0.3.4",
            versions_json=["1.0.0", "2.0.1", "3.0.2", "6.0.3.4"],
        ),
        GemMetadata(
            id="2",
            name="nokogiri",
            latest="1.4.4.1",
            versions_json=["1.0.5", "1.0.6", "1.2.7", "1.4.4.1"],
        ),
        GemMetadata(
            id="3",
            name="builder",
            latest="3.2.4",
            versions_json=[
                "1.1.0",
                "1.2.3",
                "1.2.4",
                "2.0.0",
                "2.1.1",
                "2.1.2",
                "3.2.4",
            ],
        ),
    ]


@pytest.fixture()
def image():
    img = Image(
        id=image_id,
        user_id=user,
    )
    img.get_packages_by_type = mock_get_packages_by_type
    return img


def mock_get_packages_by_type(type):
    return [
        # latest and offical
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="rails",
            version="6.0.3.4",
            pkg_type="gem",
        ),
        # official but not latest
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="nokogiri",
            version="1.0.5",
            pkg_type="gem",
        ),
        # not latest nor official
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="builder",
            version="3.3.rc1",
            pkg_type="gem",
        ),
        # not in feed
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="unoffical_test",
            version="3.0",
            pkg_type="gem",
        ),
    ]


@pytest.fixture()
def exec_context():
    mock_db = Mock()
    mock_db.query().filter().all = gem_metadata
    return ExecutionContext(db_session=mock_db, configuration={})


@pytest.fixture()
def gems_gate():
    return gems.GemCheckGate()


def assert_fired_with_msgs(trigger, expected_msgs):
    assert trigger.did_fire
    assert {f.msg for f in trigger.fired} == expected_msgs
    return True


def test_not_latest_trigger(gems_gate, exec_context, image):
    expected_msgs = {
        "Package (nokogiri) version (1.0.5) installed but is not the latest version (1.4.4.1)",
        "Package (builder) version (3.3.rc1) installed but is not the latest version (3.2.4)",
    }

    not_latest_trigger = gems.NotLatestTrigger(parent_gate_cls=gems_gate.__class__)
    gems_gate.prepare_context(image, exec_context)

    assert not_latest_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(not_latest_trigger, expected_msgs)


def test_not_official_trigger(gems_gate, exec_context, image):
    expected_msgs = {
        "GEMNOTOFFICIAL Package (unoffical_test) in container but not in official GEM feed."
    }

    not_official_trigger = gems.NotOfficialTrigger(parent_gate_cls=gems_gate.__class__)
    gems_gate.prepare_context(image, exec_context)

    assert not_official_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(not_official_trigger, expected_msgs)


def test_bad_version_trigger(gems_gate, exec_context, image):
    expected_msgs = {
        "GEMBADVERSION Package (builder) version (3.3.rc1) installed but version is not in the official feed for this package (['1.1.0', '1.2.3', '1.2.4', '2.0.0', '2.1.1', '2.1.2', '3.2.4'])"
    }

    bad_version_trigger = gems.BadVersionTrigger(parent_gate_cls=gems_gate.__class__)
    gems_gate.prepare_context(image, exec_context)

    assert bad_version_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(bad_version_trigger, expected_msgs)


blacklist_trigger_tests = [
    {
        "trigger_params": {"name": "rails"},
        "expected_fire": True,
        "expected_msgs": {"Gem Package is blacklisted: rails"},
    },
    {
        "trigger_params": {"name": "test-not-present"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"name": "rails", "version": "6.0.3.4"},
        "expected_fire": True,
        "expected_msgs": {"Gem Package is blacklisted: rails-6.0.3.4"},
    },
    {
        "trigger_params": {"name": "rails", "version": "5.0.1"},
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", blacklist_trigger_tests)
def test_blacklisted_gem_trigger(gems_gate, exec_context, image, test_context):
    blacklisted_gem_trigger = gems.BlacklistedGemTrigger(
        parent_gate_cls=gems_gate.__class__, **test_context["trigger_params"]
    )
    gems_gate.prepare_context(image, exec_context)

    assert blacklisted_gem_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert assert_fired_with_msgs(
            blacklisted_gem_trigger, test_context["expected_msgs"]
        )
    else:
        assert not blacklisted_gem_trigger.fired
        assert len(blacklisted_gem_trigger.fired) == 0
