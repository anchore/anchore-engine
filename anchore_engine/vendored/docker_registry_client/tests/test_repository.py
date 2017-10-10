from __future__ import absolute_import

from docker_registry_client.Repository import Repository
from docker_registry_client._BaseClient import BaseClientV1, BaseClientV2
from tests.mock_registry import (mock_v1_registry,
                                 mock_v2_registry,
                                 TEST_NAMESPACE,
                                 TEST_REPO,
                                 TEST_NAME)


class TestRepository(object):
    def test_initv1(self):
        url = mock_v1_registry()
        Repository(BaseClientV1(url), TEST_REPO, namespace=TEST_NAMESPACE)

    def test_initv2(self):
        url = mock_v2_registry()
        Repository(BaseClientV2(url), TEST_NAME)
