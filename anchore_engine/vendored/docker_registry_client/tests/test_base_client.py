from __future__ import absolute_import

from docker_registry_client._BaseClient import BaseClientV1, BaseClientV2
from tests.mock_registry import (mock_v1_registry,
                                 mock_v2_registry,
                                 TEST_NAME,
                                 TEST_TAG)


class TestBaseClientV1(object):
    def test_check_status(self):
        url = mock_v1_registry()
        BaseClientV1(url).check_status()


class TestBaseClientV2(object):
    def test_check_status(self):
        url = mock_v2_registry()
        BaseClientV2(url).check_status()

    def test_get_manifest_and_digest(self):
        url = mock_v2_registry()
        manifest, digest = BaseClientV2(url).get_manifest_and_digest(TEST_NAME,
                                                                     TEST_TAG)
