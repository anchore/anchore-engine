import json
import time

import pytest

from anchore_engine.auth.common import (
    get_docker_registry_userpw,
    get_creds_by_registry,
    registry_record_matches,
)

_test_username = "tonystark"
_test_password = "potts"
_test_registry_meta = {
    "authorizationToken": "{}:{}".format(_test_username, _test_password)
}
_record_ecr = {
    "registry_type": "awsecr",
    "registry_meta": json.dumps(_test_registry_meta),
}
_record_not_ecr = {
    "registry_type": "other-registry",
    "registry_user": _test_username,
    "registry_pass": _test_password,
}
_record_ecr_inactive = {
    "registry": "docker.io",
    "record_state_key": "inactive",
    "registry_type": "awsecr",
    "registry_meta": json.dumps(_test_registry_meta),
    "registry_verify": True,
}
_record_ecr_unavailable = {
    "registry": "docker.io",
    "record_state_key": "inactive",
    "record_state_val": time.time(),  # note: technically this could yield nondeterministic results
    "registry_type": "awsecr",
    "registry_meta": json.dumps(_test_registry_meta),
    "registry_verify": True,
}


@pytest.mark.parametrize("registry_record", [_record_ecr, _record_not_ecr])
def test_get_docker_registry_userpw(registry_record):
    result = get_docker_registry_userpw(registry_record)
    assert result == (_test_username, _test_password)


def test_get_docker_registry_userpw_bad_json():
    record_ecr_bad_json = {
        "registry_type": "awsecr",
        "registry_meta": "this-is-not-valid-json!}",
    }

    with pytest.raises(Exception):
        get_docker_registry_userpw(record_ecr_bad_json)


@pytest.mark.parametrize(
    "registry,repository,registry_creds,expected",
    [
        ("docker.io", "library/node", None, (None, None, None)),
        (
            "docker.io",
            "library/node",
            [_record_ecr_inactive],
            (_test_username, _test_password, True),
        ),
    ],
)
def test_get_creds_by_registry(registry, repository, registry_creds, expected):
    result = get_creds_by_registry(registry, repository, registry_creds)
    assert result == expected


def test_get_creds_by_registry_unavailable():
    with pytest.raises(Exception):
        get_creds_by_registry("docker.io", "library/node", [_record_ecr_unavailable])


@pytest.mark.parametrize(
    "registry_record_str,registry,repository",
    [
        ("docker.io/library/centos", "docker.io", "library/centos"),
        ("docker.io", "docker.io", "centos"),
        ("docker.io", "docker.io", "myuser/myrepo"),
    ],
)
def test_registry_record_matches_exact(registry_record_str, registry, repository):
    assert registry_record_matches(registry_record_str, registry, repository)


@pytest.mark.parametrize(
    "registry_record_str,registry,repository",
    [
        ("docker.io/library/*", "docker.io", "library/centos"),
        ("docker.io/*", "docker.io", "library/centos"),
        ("gcr.io/myproject/*", "gcr.io", "myproject/myuser/myrepo"),
    ],
)
def test_registry_record_matches_wildcard(registry_record_str, registry, repository):
    assert registry_record_matches(registry_record_str, registry, repository)


@pytest.mark.parametrize(
    "registry_record_str,registry,repository",
    [
        ("docker.io", "gcr.io", "myproject/myuser"),
        ("docker.io/*", "gcr.io", "myproject/myuser"),
        ("docker.io/library/*", "docker.io", "myuser/myrepo"),
        ("docker.io/myuser/myrepo", "docker.io", "myuser/myrepo2"),
    ],
)
def test_registry_record_matches_non(registry_record_str, registry, repository):
    assert not registry_record_matches(registry_record_str, registry, repository)
