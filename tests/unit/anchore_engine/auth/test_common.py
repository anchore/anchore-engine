import pytest
import json
import time
from anchore_engine.auth.common import get_docker_registry_userpw, get_creds_by_registry, registry_record_matches

_test_username = 'tonystark'
_test_password = 'potts'
_test_registry_meta = {
    'authorizationToken': '{}:{}'.format(_test_username, _test_password)
}

def test_get_docker_registry_userpw():
    record_ecr = {
        'registry_type': 'awsecr',
        'registry_meta': json.dumps(_test_registry_meta),
    }
    record_ecr_bad_json = {
        'registry_type': 'awsecr',
        'registry_meta': 'this-is-not-valid-json!}',
    }
    record_not_ecr = {
        'registry_type': 'other-registry',
        'registry_user': _test_username,
        'registry_pass': _test_password,
    }

    test_cases = [
        {
            'record': record_ecr,
            'expected': (_test_username, _test_password),
        },
        {
            'record': record_ecr_bad_json,
            'should_raise_exception': True,
        },
        {
            'record': record_not_ecr,
            'expected': (_test_username, _test_password),
        },
    ]

    for case in test_cases:
        try:
            result = get_docker_registry_userpw(case['record'])
            assert(result == case['expected'])
        except Exception:
            assert(case['should_raise_exception'])


def test_get_creds_by_registry():
    registry_verify = True

    creds = [
        {
            'registry': 'docker.io',
            'record_state_key': 'inactive',
            'registry_type': 'awsecr',
            'registry_meta': json.dumps(_test_registry_meta),
            'registry_verify': registry_verify,
        }
    ]

    creds_for_unavailable_registry = [
        {
            'registry': 'docker.io',
            'record_state_key': 'inactive',
            'record_state_val': time.time(), # note: technically this could yield nondeterministic results
            'registry_type': 'awsecr',
            'registry_meta': json.dumps(_test_registry_meta),
            'registry_verify': registry_verify,
        }
    ]

    test_cases = [
        {
            'registry': 'docker.io',
            'repository': 'library/node',
            'registry_creds': None,
            'expected': (None, None, None)
        },
        {
            'registry': 'docker.io',
            'repository': 'library/node',
            'registry_creds': creds,
            'expected': (_test_username, _test_password, registry_verify)
        },
        {
            'registry': 'docker.io',
            'repository': 'library/node',
            'registry_creds': creds_for_unavailable_registry,
            'should_raise_exception': True,
        }
    ]

    for case in test_cases:
        try:
            result = get_creds_by_registry(case['registry'], case['repository'], case['registry_creds'])
            assert(result == case['expected'])
        except Exception:
            assert(case['should_raise_exception'])


def test_registry_record_matches():
    exact_matches = [
        ('docker.io/library/centos', 'docker.io', 'library/centos'),
        ('docker.io', 'docker.io', 'centos'),
        ('docker.io', 'docker.io', 'myuser/myrepo')
    ]

    wildcard_matches = [
        ('docker.io/library/*', 'docker.io', 'library/centos'),
        ('docker.io/*', 'docker.io', 'library/centos'),
        ('gcr.io/myproject/*', 'gcr.io', 'myproject/myuser/myrepo')
    ]

    non_match = [
        ('docker.io', 'gcr.io', 'myproject/myuser'),
        ('docker.io/*', 'gcr.io', 'myproject/myuser'),
        ('docker.io/library/*', 'docker.io', 'myuser/myrepo'),
        ('docker.io/myuser/myrepo', 'docker.io', 'myuser/myrepo2')
    ]

    for test in exact_matches:
        assert(registry_record_matches(test[0], test[1], test[2]))

    for test in wildcard_matches:
        assert(registry_record_matches(test[0], test[1], test[2]))

    for test in non_match:
        assert(not registry_record_matches(test[0], test[1], test[2]))
