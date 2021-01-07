import pytest

from anchore_engine.services.analyzer.analysis import is_analysis_message

message_matrix = [
    (
        {
            "imageDigest": "sha256:1861023544345fc0a4b2223f2bcbb0e903ff2c1f29c09141250baf7f81333b49",
            "manifest": '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472, "digest": "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2814864, "digest": "sha256:0a6724ff3fcd51338afdfdc2b1d4ffd04569818e31efad957213d67c29b45101"}]}',
            "parent_manifest": None,
            "userId": "admin",
        },
        True,
    ),
    (
        {
            "imageDigest": "sha256:1861023544345fc0a4b2223f2bcbb0e903ff2c1f29c09141250baf7f81333b49",
            "manifest": '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472, "digest": "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2814864, "digest": "sha256:0a6724ff3fcd51338afdfdc2b1d4ffd04569818e31efad957213d67c29b45101"}]}',
            "parent_manifest": "",
            "userId": "admin",
        },
        True,
    ),
    (
        {
            "imageDigest": "sha256:1861023544345fc0a4b2223f2bcbb0e903ff2c1f29c09141250baf7f81333b49",
            "manifest": '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472, "digest": "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2814864, "digest": "sha256:0a6724ff3fcd51338afdfdc2b1d4ffd04569818e31efad957213d67c29b45101"}]}',
            "parent_manifest": '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472, "digest": "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2814864, "digest": "sha256:0a6724ff3fcd51338afdfdc2b1d4ffd04569818e31efad957213d67c29b45101"}]}',
            "userId": "admin",
        },
        True,
    ),
    (
        {
            "imageDigest": "sha256:1861023544345fc0a4b2223f2bcbb0e903ff2c1f29c09141250baf7f81333b49",
            "manifest": None,
            "parent_manifest": '{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 1472, "digest": "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e"}, "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": 2814864, "digest": "sha256:0a6724ff3fcd51338afdfdc2b1d4ffd04569818e31efad957213d67c29b45101"}]}',
            "userId": "admin",
        },
        False,
    ),
    (
        {
            "userId": "account1",
            "imageDigest": "sha256:abc",
            "manifest": None,
            "parent_manifest": None,
        },
        False,
    ),
    (
        {
            "userId": None,
            "imageDigest": "sha256:abc",
            "manifest": None,
            "parent_manifest": None,
        },
        False,
    ),
    (
        {
            "userId": "admin",
            "imageDigest": None,
            "manifest": None,
            "parent_manifest": None,
        },
        False,
    ),
    (
        {
            "userId": "admin",
            "imageDigest": "sha256:abc123",
        },
        False,
    ),
]


@pytest.mark.parametrize(("message", "is_analysis"), message_matrix)
def test_is_import_message(message: dict, is_analysis: bool):
    assert is_analysis_message(message) == is_analysis
