import pytest

from anchore_engine.db.entities.policy_engine import AnalysisArtifact, Image
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import passwd_file

image_id = "1"
user = "admin"
digest = "1"
redis_p_entry = "redis:x:41:29:redis:/var/redis:/bin/zsh"
foo_p_entry = "foo:x:45:45:foo:/var/foo:/bin/bash"


@pytest.fixture()
def create_image(monkeypatch):
    def _create_image(artifact_key):
        monkeypatch.setattr(
            Image,
            "analysis_artifacts",
            MockAnalysisArtifacts(artifact_key),
            raising=True,
        )

        img = Image()
        img.id = image_id
        img.digest = digest
        img.user_id = user
        return img

    return _create_image


class MockAnalysisArtifacts:
    def __init__(self, artifact_key):
        artifact1 = AnalysisArtifact()
        artifact1.analyzer_id = "retrieve_files"
        artifact1.analyzer_artifact = "file_content.all"
        artifact1.artifact_key = artifact_key
        artifact1.analyzer_type = "base"
        artifact1.image_id = image_id
        artifact1.image_user_id = user
        artifact1.binary_value = (
            "root:x:0:0:root:/root:/bin/sh\n"
            "bin:x:1:1:bin:/bin:/usr/bin/false\n"
            "adm:x:22:22:adm:/var/adm:/usr/bin/false\n"
            f"{redis_p_entry}\n"
            f"{foo_p_entry}\n"
        )

        self.artifacts = [artifact1]

    def __call__(self, *args, **kwargs):
        return self.artifacts

    def __iter__(self):
        return self.artifacts.__iter__()

    def filter(self, *args, **kwargs):
        a = [
            artifact
            for artifact in self.artifacts
            if artifact.artifact_key == "/etc/passwd"
        ]

        class A:
            def first(self):
                return a[0] if len(a) > 0 else None

        return A()


@pytest.fixture()
def passwd_gate():
    return passwd_file.FileparsePasswordGate()


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


@pytest.fixture()
def file_not_stored_trigger(passwd_gate):
    return passwd_file.FileNotStoredTrigger(parent_gate_cls=passwd_gate.__class__)


@pytest.fixture()
def make_username_match_trigger(passwd_gate):
    def _make_username_match_trigger(trigger_params):
        return passwd_file.UsernameMatchTrigger(
            parent_gate_cls=passwd_gate.__class__, **trigger_params
        )

    return _make_username_match_trigger


@pytest.fixture()
def make_user_id_match_trigger(passwd_gate):
    def _make_user_id_match_trigger(trigger_params):
        return passwd_file.UserIdMatchTrigger(
            parent_gate_cls=passwd_gate.__class__, **trigger_params
        )

    return _make_user_id_match_trigger


@pytest.fixture()
def make_group_id_match_trigger(passwd_gate):
    def _make_group_id_match_trigger(trigger_params):
        return passwd_file.GroupIdMatchTrigger(
            parent_gate_cls=passwd_gate.__class__, **trigger_params
        )

    return _make_group_id_match_trigger


@pytest.fixture()
def make_shell_match_trigger(passwd_gate):
    def _make_shell_match_trigger(trigger_params):
        return passwd_file.ShellMatchTrigger(
            parent_gate_cls=passwd_gate.__class__, **trigger_params
        )

    return _make_shell_match_trigger


@pytest.fixture()
def make_p_entry_match_trigger(passwd_gate):
    def _make_p_entry_match_trigger(trigger_params):
        return passwd_file.PEntryMatchTrigger(
            parent_gate_cls=passwd_gate.__class__, **trigger_params
        )

    return _make_p_entry_match_trigger


@pytest.fixture()
def make_trigger(
    file_not_stored_trigger,
    make_username_match_trigger,
    make_user_id_match_trigger,
    make_group_id_match_trigger,
    make_shell_match_trigger,
    make_p_entry_match_trigger,
):
    def _make_trigger(type, trigger_params):
        if type == "file_not_stored":
            return file_not_stored_trigger
        elif type == "username_match":
            return make_username_match_trigger(trigger_params)
        elif type == "user_id_match":
            return make_user_id_match_trigger(trigger_params)
        elif type == "group_id_match":
            return make_group_id_match_trigger(trigger_params)
        elif type == "shell_match":
            return make_shell_match_trigger(trigger_params)
        elif type == "p_entry_match":
            return make_p_entry_match_trigger(trigger_params)

    return _make_trigger


file_not_stored_trigger_tests = [
    {
        "trigger_type": "file_not_stored",
        "artifact_key": "other",
        "expected_fire": True,
        "expected_msgs": [passwd_file.FileNotStoredTrigger.__msg__],
    }
]

adm_blacklist_msg = "Blacklisted user 'adm' found in image's /etc/passwd: pentry=adm:x:22:22:adm:/var/adm:/usr/bin/false"
username_match_trigger_tests = [
    {
        "trigger_type": "username_match",
        "trigger_params": {"user_names": "adm"},
        "expected_fire": True,
        "expected_msgs": [adm_blacklist_msg],
    },
    {
        "trigger_type": "username_match",
        "trigger_params": {"user_names": "adm,bin"},
        "expected_fire": True,
        "expected_msgs": [
            "Blacklisted user 'bin' found in image's /etc/passwd: pentry=bin:x:1:1:bin:/bin:/usr/bin/false",
            adm_blacklist_msg,
        ],
    },
    {
        "trigger_type": "username_match",
        "trigger_params": {"user_names": "postgres"},
        "expected_fire": False,
    },
]

uid_22_blacklist_msg = "Blacklisted uid '22' found in image's /etc/passwd: pentry=adm:x:22:22:adm:/var/adm:/usr/bin/false"
user_id_match_trigger_tests = [
    {
        "trigger_type": "user_id_match",
        "trigger_params": {"user_ids": "22"},
        "expected_fire": True,
        "expected_msgs": [uid_22_blacklist_msg],
    },
    {
        "trigger_type": "user_id_match",
        "trigger_params": {"user_ids": "22,41"},
        "expected_fire": True,
        "expected_msgs": [
            f"Blacklisted uid '41' found in image's /etc/passwd: pentry={redis_p_entry}",
            uid_22_blacklist_msg,
        ],
    },
    {
        "trigger_type": "user_id_match",
        "trigger_params": {"user_ids": "220"},
        "expected_fire": False,
    },
]

group_id_match_trigger_tests = [
    {
        "trigger_type": "group_id_match",
        "trigger_params": {"group_ids": "22"},
        "expected_fire": True,
        "expected_msgs": [
            "Blacklisted gid '22' found in image's /etc/passwd: pentry=adm:x:22:22:adm:/var/adm:/usr/bin/false"
        ],
    },
    {
        "trigger_type": "group_id_match",
        "trigger_params": {"group_ids": "22,29"},
        "expected_fire": True,
        "expected_msgs": [
            "Blacklisted gid '22' found in image's /etc/passwd: pentry=adm:x:22:22:adm:/var/adm:/usr/bin/false",
            f"Blacklisted gid '29' found in image's /etc/passwd: pentry={redis_p_entry}",
        ],
    },
    {
        "trigger_type": "group_id_match",
        "trigger_params": {"group_ids": "92"},
        "expected_fire": False,
    },
]


bash_blacklist_msg = (
    f"Blacklisted shell '/bin/bash' found in image's /etc/passwd: pentry={foo_p_entry}"
)
shell_match_trigger_tests = [
    {
        "trigger_type": "shell_match",
        "trigger_params": {"shells": "/bin/bash"},
        "expected_fire": True,
        "expected_msgs": [bash_blacklist_msg],
    },
    {
        "trigger_type": "shell_match",
        "trigger_params": {"shells": "/bin/bash,/bin/zsh"},
        "expected_fire": True,
        "expected_msgs": [
            bash_blacklist_msg,
            f"Blacklisted shell '/bin/zsh' found in image's /etc/passwd: pentry={redis_p_entry}",
        ],
    },
    {
        "trigger_type": "shell_match",
        "trigger_params": {"shells": "/bin/ion"},
        "expected_fire": False,
    },
]

p_entry_match_trigger_tests = [
    {
        "trigger_type": "p_entry_match",
        "trigger_params": {"entry": redis_p_entry},
        "expected_fire": True,
        "expected_msgs": [
            f"Blacklisted pentry '{redis_p_entry}' found in image's /etc/passwd: pentry={redis_p_entry}"
        ],
    },
    {
        "trigger_type": "p_entry_match",
        "trigger_params": {"entry": foo_p_entry},
        "expected_fire": True,
        "expected_msgs": [
            f"Blacklisted pentry '{foo_p_entry}' found in image's /etc/passwd: pentry={foo_p_entry}"
        ],
    },
    {
        "trigger_type": "p_entry_match",
        "trigger_params": {
            "entry": "postgres:x:10:10:postgres:/var/postgres:/bin/false"
        },
        "expected_fire": False,
    },
]

test_contexts = [
    *file_not_stored_trigger_tests,
    *username_match_trigger_tests,
    *user_id_match_trigger_tests,
    *group_id_match_trigger_tests,
    *shell_match_trigger_tests,
    *p_entry_match_trigger_tests,
]


@pytest.mark.parametrize("test_context", test_contexts)
def test_triggers(passwd_gate, make_trigger, exec_context, create_image, test_context):
    image = create_image(test_context.get("artifact_key", "/etc/passwd"))
    trigger = make_trigger(
        test_context["trigger_type"], test_context.get("trigger_params", {})
    )
    passwd_gate.prepare_context(image, exec_context)

    assert trigger.execute(image, exec_context)
    if test_context["expected_fire"]:
        assert trigger.did_fire
        assert set(test_context["expected_msgs"]) == {
            fired.msg for fired in trigger.fired
        }
    else:
        assert not trigger.did_fire
