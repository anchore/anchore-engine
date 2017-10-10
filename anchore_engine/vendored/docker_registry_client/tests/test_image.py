from __future__ import absolute_import

from docker_registry_client.Image import Image
from docker_registry_client._BaseClient import BaseClientV1
from tests.mock_registry import mock_v1_registry


class TestImage(object):
    def test_init(self):
        url = mock_v1_registry()
        image_id = 'test_image_id'
        image = Image(image_id, BaseClientV1(url))
        assert image.image_id == image_id
