import pytest

from anchore_engine.db.entities.policy_engine import Image
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import dockerfile

image_id = "1"
user = "admin"
dockerfile_contents = """FROM ubuntu:18.04
USER admin
COPY . /app
RUN make /app
CMD python /app/app.py
EXPOSE 3000
"""


@pytest.fixture()
def create_image():
    def _create_image(dockerfile_mode="actual"):
        img = Image()
        img.id = image_id
        img.user_id = user
        img.dockerfile_contents = dockerfile_contents
        img.dockerfile_mode = dockerfile_mode
        return img

    return _create_image


@pytest.fixture()
def dockerfile_gate():
    return dockerfile.DockerfileGate()


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


@pytest.fixture()
def no_dockerfile_trigger(dockerfile_gate):
    return dockerfile.NoDockerfile(parent_gate_cls=dockerfile_gate.__class__)


@pytest.fixture()
def make_effective_user_trigger(dockerfile_gate):
    def _make_effective_user_trigger(trigger_params):
        return dockerfile.EffectiveUserTrigger(
            parent_gate_cls=dockerfile_gate.__class__, **trigger_params
        )

    return _make_effective_user_trigger


@pytest.fixture()
def make_exposed_ports_trigger(dockerfile_gate):
    def _make_exposed_ports_trigger(trigger_params):
        return dockerfile.ExposedPortsTrigger(
            parent_gate_cls=dockerfile_gate.__class__, **trigger_params
        )

    return _make_exposed_ports_trigger


@pytest.fixture()
def make_instruction_check_trigger(dockerfile_gate):
    def _make_instruction_check_trigger(trigger_params):
        return dockerfile.InstructionCheckTrigger(
            parent_gate_cls=dockerfile_gate.__class__, **trigger_params
        )

    return _make_instruction_check_trigger


@pytest.fixture()
def make_trigger(
    dockerfile_gate,
    make_effective_user_trigger,
    make_exposed_ports_trigger,
    make_instruction_check_trigger,
    no_dockerfile_trigger,
):
    def _make_trigger(type, trigger_params):
        if type == "no_dockerfile":
            return no_dockerfile_trigger
        elif type == "effective_user":
            return make_effective_user_trigger({**trigger_params})
        elif type == "instruction_check":
            return make_instruction_check_trigger({**trigger_params})
        elif type == "exposed_port":
            return make_exposed_ports_trigger({**trigger_params})

    return _make_trigger


no_dockerfile_trigger_tests = [
    {"trigger_type": "no_dockerfile", "trigger_params": {}, "expected_fire": False},
    {
        "trigger_type": "no_dockerfile",
        "trigger_params": {},
        "expected_fire": True,
        "dockerfile_mode": "guessed",
        "expected_msg": dockerfile.NoDockerfile.__msg__,
    },
    {
        "trigger_type": "no_dockerfile",
        "trigger_params": {},
        "expected_fire": True,
        "dockerfile_mode": None,
        "expected_msg": dockerfile.NoDockerfile.__msg__,
    },
]

effective_user_trigger_tests = [
    {
        "trigger_type": "effective_user",
        "trigger_params": {"users": "testUser,admin", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "User admin found as effective user, which is explicity not allowed",
    },
    {
        "trigger_type": "effective_user",
        "trigger_params": {"users": "testUser", "type": "blacklist"},
        "expected_fire": False,
    },
    {
        "trigger_type": "effective_user",
        "trigger_params": {"users": "admin", "type": "whitelist"},
        "expected_fire": False,
    },
    {
        "trigger_type": "effective_user",
        "trigger_params": {"users": "admin", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "User admin found as effective user, which is explicity not allowed",
    },
]

exposed_port_trigger_tests = [
    {
        "trigger_type": "exposed_port",
        "trigger_params": {"ports": "2800,3000", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "Dockerfile exposes port (3000) which is in policy file DENIEDPORTS list",
    },
    {
        "trigger_type": "exposed_port",
        "trigger_params": {"ports": "2800", "type": "blacklist"},
        "expected_fire": False,
    },
    {
        "trigger_type": "exposed_port",
        "trigger_params": {"ports": "3000", "type": "whitelist"},
        "expected_fire": False,
    },
    {
        "trigger_type": "exposed_port",
        "trigger_params": {"ports": "2800,3001", "type": "whitelist"},
        "expected_fire": True,
        "expected_msg": "Dockerfile exposes port (3000) which is not in policy file ALLOWEDPORTS list",
    },
]

instruction_check_trigger_tests = [
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "=", "value": ". /app"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check '=' matched against '. /app' for line '. /app'",
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "!=", "value": ". /app"},
        "expected_fire": False,
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "exists"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'exists' matched against '' for line '. /app'",
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "VOLUME", "check": "not_exists"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'VOLUME' not found, matching condition 'not_exists' check",
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "not_exists"},
        "expected_fire": False,
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "like", "value": ". /"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'like' matched against '. /' for line '. /app'",
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {
            "instruction": "COPY",
            "check": "like",
            "value": ". /usr/local/bin",
        },
        "expected_fire": False,
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {
            "instruction": "COPY",
            "check": "not_like",
            "value": ". /usr",
        },
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'not_like' matched against '. /usr' for line '. /app'",
    },
    {
        "trigger_type": "instruction_check",
        "trigger_params": {
            "instruction": "COPY",
            "check": "not_like",
            "value": ". /app",
        },
        "expected_fire": False,
    },
]

actual_dockerfile_only_tests = [
    {
        "trigger_type": "instruction_check",
        "trigger_params": {
            "actual_dockerfile_only": True,
            "instruction": "COPY",
            "check": "exists",
        },
        "expected_fire": False,
        "dockerfile_mode": None,
    },
    {
        "trigger_type": "exposed_port",
        "trigger_params": {
            "actual_dockerfile_only": True,
            "ports": "3000",
            "type": "blacklist",
        },
        "expected_fire": False,
        "dockerfile_mode": None,
    },
]

test_contexts = [
    *no_dockerfile_trigger_tests,
    *effective_user_trigger_tests,
    *exposed_port_trigger_tests,
    *instruction_check_trigger_tests,
    *actual_dockerfile_only_tests,
]


@pytest.mark.parametrize("test_context", test_contexts)
def test_variable_trigger_when_dockerfile_present(
    dockerfile_gate, make_trigger, exec_context, create_image, test_context
):
    image = create_image(test_context.get("dockerfile_mode", "actual"))
    trigger = make_trigger(
        test_context["trigger_type"], test_context.get("trigger_params", {})
    )

    dockerfile_gate.prepare_context(image, exec_context)
    assert trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert trigger.did_fire
        assert len(trigger.fired) == 1
        assert trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert trigger.did_fire is False
