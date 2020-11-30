import pytest
import zlib
import json
from anchore_engine.services.policy_engine.engine.policy.gates import files
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db.entities.policy_engine import (
    Image,
    FilesystemAnalysis,
    AnalysisArtifact,
)

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
    }
    fs = FilesystemAnalysis(
        compressed_file_json=zlib.compress(json.dumps(files_json).encode()),
        compression_algorithm="gzip",
    )

    return Image(id="image_id", user_id="user", fs=fs)


class MockAnalysisArtifacts:
    def __init__(self):
        artifact = AnalysisArtifact()
        artifact.analyzer_id = "content_search"
        artifact.analyzer_artifact = "regexp_matches.all"
        artifact.analyzer_type = "base"
        artifact.image_id = image_id
        artifact.image_user_id = user

        self.artifacts = [artifact]

    def __call__(self, *args, **kwargs):
        return self.artifacts

    def __iter__(self):
        return self.artifacts.__iter__()

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


# TODO add content match trigger tests
