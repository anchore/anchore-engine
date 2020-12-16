import pytest

from anchore_engine.services.analyzer.imports import is_import_message

message_matrix = [
    (
        {
            "userId": "account1",
            "imageDigest": "sha256:abc123def456",
            "manifest": {
                "tags": ["sometag"],
                "digest": "sha256:abc123def456",
                "local_image_id": "sha256:def",
                "contents": [
                    {
                        "content_type": "packages",
                        "digest": "sha256:abc",
                        "bucket": "import_data",
                        "key": "somevalue",
                    },
                    {
                        "content_type": "dockerfile",
                        "digest": "sha256:abc",
                        "bucket": "import_data",
                        "key": "somevalue",
                    },
                    {
                        "content_type": "manifest",
                        "digest": "sha256:abc",
                        "bucket": "import_data",
                        "key": "somevalue",
                    },
                ],
                "operation_uuid": "someid",
            },
            "parent_manifest": None,
        },
        True,
    ),
    (
        {
            "userId": "account1",
            "imageDigest": "sha256:abc",
            "manifest": "",
            "parent_manifest": "",
        },
        False,
    ),
]


@pytest.mark.parametrize(("message", "is_import"), message_matrix)
def test_is_import_message(message: dict, is_import: bool):
    assert is_import_message(message) == is_import
