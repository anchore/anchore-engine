from unittest.mock import Mock

import pytest

from anchore_engine.db.entities.policy_engine import Image, ImagePackage, NpmMetadata
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import npms

image_id = "1"
user = "admin"


def npm_metadata():
    return [
        NpmMetadata(
            name="yarn",
            latest="1.22.10",
            versions_json=["0.1.0", "0.3", "0.5.2", "1.22.10"],
        ),
        NpmMetadata(
            name="jsonparse",
            latest="1.3.1",
            versions_json=[
                "0.0.5",
                "0.0.4",
                "0.0.6",
                "1.1.0",
                "1.3.1",
            ],
        ),
        NpmMetadata(
            name="ini",
            latest="1.3.5",
            versions_json=["1.3.0", "1.3.5", "1.2.0", "1.2.1"],
        ),
    ]


@pytest.fixture()
def image():
    img = Image(id=image_id, user_id=user)
    img.get_packages_by_type = mock_get_packages_by_type
    return img


def mock_get_packages_by_type(type):
    return [
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            pkg_type="npm",
            name="yarn",
            version="1.22.10",
        ),
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            pkg_type="npm",
            name="jsonparse",
            version="1.1.0",
        ),
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            pkg_type="npm",
            name="ini",
            version="1.0.0",
        ),
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            pkg_type="npm",
            name="unofficial-test",
            version="1.3.1",
        ),
    ]


@pytest.fixture()
def exec_context():
    mock_db = Mock()
    mock_db.query().filter().all = npm_metadata
    return ExecutionContext(db_session=mock_db, configuration={})


@pytest.fixture()
def npms_gate():
    return npms.NpmCheckGate()


def assert_fired_with_msgs(trigger, expected_msgs):
    assert trigger.did_fire
    assert {f.msg for f in trigger.fired} == expected_msgs
    return True


def test_not_latest_trigger(image, exec_context, npms_gate):
    expected_msgs = {
        "NPMNOTLATEST Package (jsonparse) version (1.1.0) installed but is not the latest version (1.3.1)",
        "NPMNOTLATEST Package (ini) version (1.0.0) installed but is not the latest version (1.3.5)",
    }
    not_latest_trigger = npms.NotLatestTrigger(parent_gate_cls=npms_gate.__class__)
    npms_gate.prepare_context(image, exec_context)

    assert not_latest_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(not_latest_trigger, expected_msgs)


def test_not_official_trigger(image, exec_context, npms_gate):
    expected_msgs = {
        "NPMNOTOFFICIAL Package (unofficial-test) in container but not in official NPM feed."
    }

    not_official_trigger = npms.NotOfficialTrigger(parent_gate_cls=npms_gate.__class__)
    npms_gate.prepare_context(image, exec_context)

    assert not_official_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(not_official_trigger, expected_msgs)


def test_bad_version_trigger(image, exec_context, npms_gate):
    expected_msgs = {
        "NPMBADVERSION Package (ini) version (1.0.0) installed but version is not in the official feed for this package (['1.3.0', '1.3.5', '1.2.0', '1.2.1'])"
    }

    bad_version_trigger = npms.BadVersionTrigger(parent_gate_cls=npms_gate.__class__)
    npms_gate.prepare_context(image, exec_context)

    assert bad_version_trigger.execute(image, exec_context)
    assert assert_fired_with_msgs(bad_version_trigger, expected_msgs)


pkg_match_trigger_tests = [
    {
        "trigger_params": {"name": "yarn"},
        "expected_fire": True,
        "expected_msgs": {"NPM Package is blacklisted: yarn"},
    },
    {"trigger_params": {"name": "no-match"}, "expected_fire": False},
    {
        "trigger_params": {"name": "ini", "version": "1.0.0"},
        "expected_fire": True,
        "expected_msgs": {"NPM Package is blacklisted: ini-1.0.0"},
    },
    {"trigger_params": {"name": "ini", "version": "2.3.2"}, "expected_fire": False},
]


@pytest.mark.parametrize("test_context", pkg_match_trigger_tests)
def test_pkg_match_trigger(image, exec_context, npms_gate, test_context):
    pkg_match_trigger = npms.PkgMatchTrigger(
        parent_gate_cls=npms_gate.__class__, **test_context["trigger_params"]
    )

    npms_gate.prepare_context(image, exec_context)

    assert pkg_match_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert assert_fired_with_msgs(pkg_match_trigger, test_context["expected_msgs"])
    else:
        assert not pkg_match_trigger.did_fire
        assert len(pkg_match_trigger.fired) == 0
