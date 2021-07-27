from unittest import TestCase

import pytest

from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.catalog import catalog_impl

# This looks unused, but it is


@pytest.mark.skip(
    reason="hard to install skopeo (which is needed for this test) in the integration test environment"
)
class TestImageAddWorkflow:
    """
    This verifies that getting image info with full registry lookup (manifest, etc.) works well via skopeo
    """

    expected_full_image_info = {
        "host": "docker.io",
        "port": None,
        "repo": "anchore/test_images",
        "tag": None,
        "registry": "docker.io",
        "repotag": None,
        "fulltag": None,
        "digest": "sha256:2dceaabe73ee43341b0ab79aaa10f8d0c79b7866d9b4c31e1923a32e9cc4b586",
        "fulldigest": "docker.io/anchore/test_images@sha256:2dceaabe73ee43341b0ab79aaa10f8d0c79b7866d9b4c31e1923a32e9cc4b586",
        "imageId": "9643331146c7f23baf4598b225f319c63fa9ee67c5d66c93a8ec08f5ff9b2e8f",
        "pullstring": "docker.io/anchore/test_images@sha256:2dceaabe73ee43341b0ab79aaa10f8d0c79b7866d9b4c31e1923a32e9cc4b586",
        "manifest": {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 2491,
                "digest": "sha256:9643331146c7f23baf4598b225f319c63fa9ee67c5d66c93a8ec08f5ff9b2e8f",
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": 75181999,
                    "digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
                },
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": 41036387,
                    "digest": "sha256:f2a5547a54a758257753cf3d0fff976527fa6eb163733911d93b18f0089ec426",
                },
            ],
        },
        "parentmanifest": {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 2491,
                "digest": "sha256:9643331146c7f23baf4598b225f319c63fa9ee67c5d66c93a8ec08f5ff9b2e8f",
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": 75181999,
                    "digest": "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621",
                },
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": 41036387,
                    "digest": "sha256:f2a5547a54a758257753cf3d0fff976527fa6eb163733911d93b18f0089ec426",
                },
            ],
        },
        "parentdigest": "sha256:2dceaabe73ee43341b0ab79aaa10f8d0c79b7866d9b4c31e1923a32e9cc4b586",
        "compressed_size": 116218386,
    }

    def test_resolve_final_image_info(self, anchore_db):
        input_string = "anchore/test_images@sha256:2dceaabe73ee43341b0ab79aaa10f8d0c79b7866d9b4c31e1923a32e9cc4b586"
        session = get_thread_scoped_session()
        actual_image_info = catalog_impl.resolve_final_image_info(
            "admin", input_string, [], session, {}
        )
        test_case = TestCase()
        test_case.maxDiff = None
        test_case.assertDictEqual(self.expected_full_image_info, actual_image_info)
