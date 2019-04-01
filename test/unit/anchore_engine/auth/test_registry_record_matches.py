import pytest
from anchore_engine.auth.common import registry_record_matches

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




