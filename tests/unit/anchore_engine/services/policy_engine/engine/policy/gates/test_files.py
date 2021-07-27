import json
import zlib

import pytest

from anchore_engine.db.entities.policy_engine import (
    AnalysisArtifact,
    FilesystemAnalysis,
    Image,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import files

image_id = "1"
user = "admin"


@pytest.fixture()
def image(monkeypatch):
    monkeypatch.setattr(
        Image, "analysis_artifacts", MockAnalysisArtifacts(), raising=True
    )

    files_json = {
        "/bin": {
            "fullpath": "/bin",
            "name": "/bin",
            "mode": 16877,
            "permissions": "0o755",
            "linkdst_fullpath": None,
            "linkdst": None,
            "size": 0,
            "entry_type": "dir",
            "is_packaged": True,
            "md5_checksum": "79f65df590b25155a587461aeb79eeb1",
            "sha256_checksum": "a4a080992560315f59b75c62e458181c00fe5c3b962f5b2b64297badbfbc12c7",
            "sha1_checksum": "a523ce63d9556ba950ebb81609faf00de04dd1a7",
            "othernames": [],
            "suid": None,
        },
        "/bin/arch": {
            "fullpath": "/bin/arch",
            "name": "/bin/arch",
            "mode": 41471,
            "permissions": "0o777",
            "linkdst_fullpath": "/bin/busybox",
            "linkdst": "/bin/busybox",
            "size": 12,
            "entry_type": "slink",
            "is_packaged": False,
            "md5_checksum": "87ac152a3e02d3a6a84d129422611f85",
            "sha256_checksum": "480bddf71ef05659c5405f65f139e49b99122175f0163d281d471f0a368aad7c",
            "sha1_checksum": "8d05b5d4a9ea76ec570b17e1f77ccd65a55937d9",
            "othernames": [],
            "suid": None,
        },
        "/usr/bin/test": {
            "fullpath": "/usr/bin/test",
            "name": "/usr/bin/test",
            "mode": 3072,
            "permissions": "0o777",
            "linkdst_fullpath": "/bin/busybox",
            "linkdst": "/bin/busybox",
            "size": 12,
            "entry_type": "slink",
            "is_packaged": False,
            "md5_checksum": "DIRECTORY_OR_OTHER",
            "sha256_checksum": "DIRECTORY_OR_OTHER",
            "sha1_checksum": "DIRECTORY_OR_OTHER",
            "othernames": [],
            "suid": None,
        },
        "/usr/share/apk/keys": {
            "fullpath": "/usr/share/apk/keys",
            "name": "/usr/share/apk/keys",
            "mode": 3072,
            "permissions": "0o755",
            "linkdst_fullpath": None,
            "linkdst": None,
            "size": 0,
            "entry_type": "dir",
            "is_packaged": True,
            "md5_checksum": "DIRECTORY_OR_OTHER",
            "sha256_checksum": "DIRECTORY_OR_OTHER",
            "sha1_checksum": "DIRECTORY_OR_OTHER",
            "othernames": [],
            "suid": None,
        },
        "/fake_private_key": {
            "fullpath": "/fake_aws_key",
            "name": "/fake_aws_key",
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

    return Image(id="image_id", user_id="user", fs=fs)


class MockAnalysisArtifacts:
    def __init__(self):
        self.artifacts = [
            AnalysisArtifact(
                image_id=image_id,
                image_user_id=user,
                analyzer_id="content_search",
                analyzer_artifact="regexp_matches.all",
                analyzer_type="base",
                artifact_key="/fake_aws_access_key",
                json_value={
                    "QVdTX0FDQ0VTU19LRVk9KD9pKS4qYXdzX2FjY2Vzc19rZXlfaWQoICo9KyAqKS4qKD88IVtBLVow\nLTldKVtBLVowLTldezIwfSg/IVtBLVowLTldKS4q\n": [
                        0
                    ]
                },
            ),
            AnalysisArtifact(
                image_id=image_id,
                image_user_id=user,
                analyzer_id="content_search",
                analyzer_artifact="regexp_matches.all",
                analyzer_type="base",
                artifact_key="/fake_api_key",
                json_value={
                    "QVBJX0tFWT0oP2kpLiphcGkoLXxfKWtleSggKj0rICopLiooPzwhW0EtWjAtOV0pW0EtWjAtOV17\nMjAsNjB9KD8hW0EtWjAtOV0pLio=\n": [
                        0
                    ]
                },
            ),
        ]

    def filter(self, *args, **kwargs):
        a = self.artifacts

        class A:
            def all(self):
                return a

        return A()


@pytest.fixture()
def files_gate():
    return files.FileCheckGate()


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


def base_trigger_assertions(trigger, test_context):
    if test_context["expected_fire"]:
        assert trigger.did_fire
        assert set(test_context["expected_msgs"]) == {
            fired.msg for fired in trigger.fired
        }
    else:
        assert not trigger.did_fire
        assert len(trigger.fired) == 0

    return True


filename_match_trigger_tests = [
    {
        "regex": ".*arch",
        "expected_fire": True,
        "expected_msgs": [
            "Application of regex matched file found in container: file=/bin/arch regexp=.*arch"
        ],
    },
    {
        "regex": "/usr/local/bin",
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", filename_match_trigger_tests)
def test_filename_match_trigger(files_gate, exec_context, image, test_context):
    filename_match_trigger = files.FilenameMatchTrigger(
        parent_gate_cls=files_gate.__class__, regex=test_context["regex"]
    )

    files_gate.prepare_context(image, exec_context)

    assert filename_match_trigger.execute(image, exec_context)

    assert base_trigger_assertions(filename_match_trigger, test_context)


file_attribute_match_trigger_tests = [
    {
        "trigger_params": {
            "filename": "/bin/arch",
            "checksum_algorithm": "sha256",
            "checksum": "5a05c656df50a3d9fb6a299716196a28dd33dc55d154fd72d9bab89a5e1815ab",
            "checksum_match": "equals",
        },
        "expected_fire": False,
    },
    {
        "trigger_params": {
            "filename": "/bin/arch",
            "checksum_algorithm": "sha256",
            "checksum": "5a05c656df50a3d9fb6a299716196a28dd33dc55d154fd72d9bab89a5e1815ab",
            "checksum_match": "not_equals",
        },
        "expected_fire": True,
        "expected_msgs": [
            "filename=/bin/arch and checksum=480bddf71ef05659c5405f65f139e49b99122175f0163d281d471f0a368aad7c op=not_equals specified_checksum=5a05c656df50a3d9fb6a299716196a28dd33dc55d154fd72d9bab89a5e1815ab"
        ],
    },
    {
        "trigger_params": {
            "filename": "/bin/arch",
            "checksum_algorithm": "sha256",
            "checksum": "480bddf71ef05659c5405f65f139e49b99122175f0163d281d471f0a368aad7c",
            "checksum_match": "equals",
        },
        "expected_fire": True,
        "expected_msgs": [
            "filename=/bin/arch and checksum=480bddf71ef05659c5405f65f139e49b99122175f0163d281d471f0a368aad7c op=equals specified_checksum=480bddf71ef05659c5405f65f139e49b99122175f0163d281d471f0a368aad7c"
        ],
    },
    {
        "trigger_params": {
            "filename": "/bin/arch",
            "mode": "00777",
            "mode_op": "equals",
        },
        "expected_fire": True,
        "expected_msgs": [
            "filename=/bin/arch and mode=0o777 op=equals specified_mode=0o777"
        ],
    },
    {
        "trigger_params": {
            "filename": "/usr/local/test_file",
            "mode": "00777",
            "mode_op": "equals",
            "skip_missing": False,
        },
        "expected_fire": True,
        "expected_msgs": ["filename=/usr/local/test_file and skip_missing=False"],
    },
]


@pytest.mark.parametrize("test_context", file_attribute_match_trigger_tests)
def test_file_attribute_match_trigger(files_gate, exec_context, image, test_context):
    file_attribute_match_trigger = files.FileAttributeMatchTrigger(
        parent_gate_cls=files_gate.__class__, **test_context["trigger_params"]
    )

    files_gate.prepare_context(image, exec_context)

    assert file_attribute_match_trigger.execute(image, exec_context)

    assert base_trigger_assertions(file_attribute_match_trigger, test_context)


def test_suid_check_trigger(files_gate, exec_context, image):
    test_context = {
        "expected_fire": True,
        "expected_msgs": [
            "SUID or SGID found set on file /usr/bin/test. Mode: 0o6000",
            "SUID or SGID found set on file /usr/share/apk/keys. Mode: 0o6000",
        ],
    }
    suid_check_trigger = files.SuidCheckTrigger(parent_gate_cls=files_gate.__class__)

    files_gate.prepare_context(image, exec_context)

    assert suid_check_trigger.execute(image, exec_context)

    assert base_trigger_assertions(suid_check_trigger, test_context)


content_match_trigger_tests = [
    {
        "trigger_params": {"regex_name": "AWS_ACCESS_KEY"},
        "expected_fire": True,
        "expected_msgs": [
            "File content analyzer found regexp match in container: file=/fake_aws_access_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        ],
    },
    {
        "trigger_params": {
            "regex_name": "(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        },
        "expected_fire": True,
        "expected_msgs": [
            "File content analyzer found regexp match in container: file=/fake_aws_access_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*"
        ],
    },
    {
        "trigger_params": {},
        "expected_fire": True,
        "expected_msgs": [
            "File content analyzer found regexp match in container: file=/fake_aws_access_key regexp=AWS_ACCESS_KEY=(?i).*aws_access_key_id( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9]).*",
            "File content analyzer found regexp match in container: file=/fake_api_key regexp=API_KEY=(?i).*api(-|_)key( *=+ *).*(?<![A-Z0-9])[A-Z0-9]{20,60}(?![A-Z0-9]).*",
        ],
    },
]


@pytest.mark.parametrize("test_context", content_match_trigger_tests)
def test_content_match_trigger(files_gate, exec_context, image, test_context):
    content_match_trigger = files.ContentMatchTrigger(
        parent_gate_cls=files_gate.__class__, **test_context["trigger_params"]
    )

    files_gate.prepare_context(image, exec_context)

    assert content_match_trigger.execute(image, exec_context)

    assert base_trigger_assertions(content_match_trigger, test_context)
