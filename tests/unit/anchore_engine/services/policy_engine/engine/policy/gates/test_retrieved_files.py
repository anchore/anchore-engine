import pytest

from anchore_engine.db.entities.policy_engine import Image, AnalysisArtifact
from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    PolicyRuleValidationErrorCollection,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import retrieved_files

image_id = "1"
user = "admin"


@pytest.fixture()
def image(monkeypatch):
    monkeypatch.setattr(
        Image, "analysis_artifacts", MockAnalysisArtifacts(), raising=True
    )

    return Image(
        id=image_id,
        user_id=user,
    )


class MockAnalysisArtifacts:
    def __init__(self):
        self.artifacts = [
            AnalysisArtifact(
                analyzer_id="retrieve_files",
                analyzer_artifact="file_content.all",
                analyzer_type="base",
                artifact_key="/etc/passwd",
                binary_value="adm:x:5:5:adm:/var/adm:/bin/bash",
            ),
            AnalysisArtifact(
                analyzer_id="retrieve_files",
                analyzer_artifact="file_content.all",
                analyzer_type="base",
                artifact_key="/usr/local/lib/ruby/gems/2.3.0/",
                binary_value="adm:x:5:5:adm:/var/adm:/bin/bash",
            ),
        ]

    def __call__(self, *args, **kwargs):
        return self.artifacts

    def __iter__(self):
        return self.artifacts.__iter__()

    def filter(self, *args, **kwargs):
        a = self.artifacts

        class QueryResult:
            def all(self):
                return a

        return QueryResult()


@pytest.fixture()
def retrieved_files_gate():
    return retrieved_files.RetrievedFileChecksGate()


@pytest.fixture()
def make_file_not_stored_trigger(retrieved_files_gate):
    def _make_file_not_stored_trigger(params):
        return retrieved_files.FileNotStoredTrigger(
            parent_gate_cls=retrieved_files_gate.__class__, **params
        )

    return _make_file_not_stored_trigger


@pytest.fixture()
def make_file_content_regex_match_trigger(retrieved_files_gate):
    def _make_file_content_regex_match_trigger(params):
        return retrieved_files.FileContentRegexMatchTrigger(
            parent_gate_cls=retrieved_files_gate.__class__, **params
        )

    return _make_file_content_regex_match_trigger


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


def base_retrieve_file_trigger_assertions(trigger, test_context):
    if test_context["expected_fire"]:
        assert trigger.did_fire
        assert len(trigger.fired) == 1
        assert trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert not trigger.did_fire
        assert len(trigger.fired) == 0

    return True


file_not_stored_contexts = [
    {
        "trigger_params": {"path": "/test/path"},
        "expected_fire": True,
        "expected_msg": "Cannot locate file in the image analysis",
    },
    {
        "trigger_params": {"path": "/etc/passwd"},
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", file_not_stored_contexts)
def test_file_not_stored_trigger(
    retrieved_files_gate,
    exec_context,
    image,
    make_file_not_stored_trigger,
    test_context,
):
    file_not_stored_trigger = make_file_not_stored_trigger(
        test_context["trigger_params"]
    )
    retrieved_files_gate.prepare_context(image, exec_context)

    assert file_not_stored_trigger.execute(image, exec_context)

    assert base_retrieve_file_trigger_assertions(file_not_stored_trigger, test_context)


file_content_regex_test_contexts = [
    {
        "trigger_params": {"path": "/etc/passwd", "check": "match", "regex": ".*bash"},
        "expected_fire": True,
        "expected_msg": "Content regex '.*bash' check 'match' found in retrieved file '/etc/passwd'",
    },
    {
        "trigger_params": {"path": "/etc/passwd", "check": "match", "regex": ".*zsh"},
        "expected_fire": False,
    },
    {
        "trigger_params": {
            "path": "/etc/passwd",
            "check": "no_match",
            "regex": ".*bash",
        },
        "expected_fire": False,
    },
    {
        "trigger_params": {
            "path": "/usr/local/lib/ruby/gems/2.3.0/",
            "check": "no_match",
            "regex": "expect_fail",
        },
        "expected_fire": True,
        "expected_msg": "Content regex 'expect_fail' check 'no_match' found in retrieved file '/usr/local/lib/ruby/gems/2.3.0/'",
    },
]


@pytest.mark.parametrize("test_context", file_content_regex_test_contexts)
def test_file_content_regex_match_trigger(
    retrieved_files_gate,
    make_file_content_regex_match_trigger,
    exec_context,
    image,
    test_context,
):
    file_content_regex_match_trigger = make_file_content_regex_match_trigger(
        test_context["trigger_params"]
    )
    retrieved_files_gate.prepare_context(image, exec_context)

    assert file_content_regex_match_trigger.execute(image, exec_context)

    assert base_retrieve_file_trigger_assertions(
        file_content_regex_match_trigger, test_context
    )


exception_params = [
    {"check": "match", "regex": ".*bash"},
    {"path": "/etc/passwd", "regex": ".*bash"},
    {"path": "/etc/passwd", "check": "match"},
    {"path": "/etc/passwd", "check": "!=", "regex": ".*bash"},
]


@pytest.mark.parametrize("params", exception_params)
def test_policy_validation_error(make_file_content_regex_match_trigger, params):
    with pytest.raises(PolicyRuleValidationErrorCollection):
        make_file_content_regex_match_trigger(params)
