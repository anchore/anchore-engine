import json
import zlib

import pytest

from anchore_engine.db.entities.policy_engine import (
    Image,
    AnalysisArtifact,
    FilesystemAnalysis,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import secrets

image_id = "1"
user = "admin"


@pytest.fixture()
def image(monkeypatch):
    monkeypatch.setattr(
        Image, "analysis_artifacts", MockAnalysisArtifacts(), raising=True
    )

    files_json = {
        "/fake_private_key": {
            "fullpath": "/fake_private_key",
            "name": "/fake_private_key",
            "mode": 33188,
            "permissions": "0o644",
            "linkdst_fullpath": None,
            "linkdst": None,
            "size": 22,
            "entry_type": "file",
            "is_packaged": False,
            "md5_checksum": "f1779b586f2fda64f084fa4cda2749f4",
            "sha256_checksum": "9e6be7f96d6c88338eecb2396e4e7c27d3387fe45e5aa740614e1e292ce65aa7",
            "sha1_checksum": "9fada773ed59c05a2c5352e8eee8afa0fda3483e",
            "othernames": [],
            "suid": None,
        },
        "/fake_api_key": {
            "fullpath": "/fake_api_key",
            "name": "/fake_api_key",
            "mode": 33188,
            "permissions": "0o644",
            "linkdst_fullpath": None,
            "linkdst": None,
            "size": 32,
            "entry_type": "file",
            "is_packaged": False,
            "md5_checksum": "8e67b4af0e9b6598c901f06a74835632",
            "sha256_checksum": "77db45a31c74cf01bb130ab4bc4869d2d03b576c48977f96ae81d4e4912f334b",
            "sha1_checksum": "9d819cb21d51d3720fc74e0ee2d8242c7e5bdcf2",
            "othernames": [],
            "suid": None,
        },
    }
    fs = FilesystemAnalysis(
        compressed_file_json=zlib.compress(json.dumps(files_json).encode()),
        compression_algorithm="gzip",
    )

    return Image(id=image_id, user_id=user, fs=fs)


class MockAnalysisArtifacts:
    def __init__(self):
        self.artifacts = [
            AnalysisArtifact(
                analyzer_id="secret_search",
                analyzer_artifact="regexp_matches.all",
                analyzer_type="base",
                artifact_key="/fake_aws_key",
                json_value={
                    "QVdTX0FDQ0VTU19LRVk9KD9pKS4qYXdzX2FjY2Vzc19rZXlfaWQoICo9KyAqKS4qKD88IVtBLVow\nLTldKVtBLVowLTldezIwfSg/IVtBLVowLTldKS4q\n": [
                        0
                    ]
                },
            ),
            AnalysisArtifact(
                analyzer_id="secret_search",
                analyzer_artifact="regexp_matches.all",
                analyzer_type="base",
                artifact_key="/fake_private_key",
                json_value={
                    "UFJJVl9LRVk9KD9pKS0rQkVHSU4oLiopUFJJVkFURSBLRVktKw==\n": [0]
                },
            ),
        ]

    def filter(self, *args, **kwargs):
        a = self.artifacts

        class QueryResult:
            def all(self):
                return a

        return QueryResult()


@pytest.fixture()
def secrets_gate():
    return secrets.SecretCheckGate()


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


secret_content_tests = [
    {
        "trigger_params": {"content_regex_name": "AWS_ACCESS_KEY"},
        "expected_fire": True,
        "expected_msgs": [
            "Secret content search analyzer found regexp match in container: file=/fake_aws_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        ],
    },
    {"trigger_params": {"content_regex_name": "test"}, "expected_fire": False},
    {
        "trigger_params": {"filename_regex": "/fake*"},
        "expected_fire": True,
        "expected_msgs": [
            "Secret content search analyzer found regexp match in container: file=/fake_aws_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*",
            "Secret content search analyzer found regexp match in container: file=/fake_private_key regexp=PRIV_KEY=(?i)-+BEGIN(.*)PRIVATE KEY-+",
        ],
    },
    {"trigger_params": {"filename_regex": "/fake_test*"}, "expected_fire": False},
    {
        "trigger_params": {"filename_regex": "/fake_test*", "match_type": "notfound"},
        "expected_fire": True,
        "expected_msgs": [
            "Secret content search analyzer did not find regexp match in container: filename_regex=/fake_test* content_regex_name=all"
        ],
    },
    {
        "trigger_params": {
            "content_regex_name": "AWS_ACCESS_KEY",
            "match_type": "found",
        },
        "expected_fire": True,
        "expected_msgs": [
            "Secret content search analyzer found regexp match in container: file=/fake_aws_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        ],
    },
    {
        "trigger_params": {
            "filename_regex": "/fake*",
            "content_regex_name": "AWS_ACCESS_KEY",
        },
        "expected_fire": True,
        "expected_msgs": [
            "Secret content search analyzer found regexp match in container: file=/fake_aws_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        ],
    },
]


@pytest.mark.parametrize("test_context", secret_content_tests)
def test_secret_content_trigger(image, exec_context, secrets_gate, test_context):
    secret_content_trigger = secrets.SecretContentChecksTrigger(
        parent_gate_cls=secrets_gate.__class__, **test_context["trigger_params"]
    )

    secrets_gate.prepare_context(image, exec_context)

    assert secret_content_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert secret_content_trigger.did_fire
        assert set(test_context["expected_msgs"]) == {
            fired.msg for fired in secret_content_trigger.fired
        }
    else:
        assert not secret_content_trigger.did_fire
        assert len(secret_content_trigger.fired) == 0
