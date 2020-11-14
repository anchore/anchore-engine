import pytest
from anchore_engine.services.policy_engine.engine.policy.gates import dockerfile
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db.entities.policy_engine import Image

image_id = "1"
user = "admin"
absent_modes = ["guessed", None]
dockerfile_contents = """FROM ubuntu:18.04
USER admin
COPY . /app
RUN make /app
CMD python /app/app.py
EXPOSE 3000
"""


@pytest.fixture()
def image():
    img = Image()
    img.id = image_id
    img.user_id = user
    img.dockerfile_contents = dockerfile_contents
    img.dockerfile_mode = "actual"

    return img


@pytest.fixture()
def dockerfile_gate():
    return dockerfile.DockerfileGate()


@pytest.fixture()
def no_dockerfile_trigger(dockerfile_gate):
    return dockerfile.NoDockerfile(parent_gate_cls=dockerfile_gate.__class__)


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


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
def make_actual_dockerfile_only_trigger(
    dockerfile_gate, make_instruction_check_trigger, make_exposed_ports_trigger
):
    def _make_trigger(type, trigger_params):
        if type == "instruction_check":
            return make_instruction_check_trigger(
                {"actual_dockerfile_only": True, **trigger_params}
            )
        elif type == "exposed_port":
            return make_exposed_ports_trigger(
                {"actual_dockerfile_only": True, **trigger_params}
            )

    return _make_trigger


def test_dockerfile_present(
    dockerfile_gate, no_dockerfile_trigger, exec_context, image
):
    dockerfile_gate.prepare_context(image, exec_context)
    assert no_dockerfile_trigger.execute(image, exec_context)
    assert no_dockerfile_trigger.did_fire is False


@pytest.mark.parametrize("mode", absent_modes)
def test_dockerfile_absent(
    dockerfile_gate, no_dockerfile_trigger, exec_context, image, mode
):
    image.dockerfile_mode = mode

    dockerfile_gate.prepare_context(image, exec_context)
    assert no_dockerfile_trigger.execute(image, exec_context)
    assert no_dockerfile_trigger.did_fire
    assert no_dockerfile_trigger.fired[0].msg == dockerfile.NoDockerfile.__msg__


# Effective user tests parameterized via dict objects
# Tests in order: user in blacklist, user not in blacklist, user in whitelist, user not in whitelist
effective_user_test_contexts = [
    {
        "trigger_params": {"users": "testUser,admin", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "User admin found as effective user, which is explicity not allowed",
    },
    {
        "trigger_params": {"users": "testUser", "type": "blacklist"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"users": "admin", "type": "whitelist"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"users": "admin", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "User admin found as effective user, which is explicity not allowed",
    },
]


@pytest.mark.parametrize("test_context", effective_user_test_contexts)
def test_effective_user_trigger(
    dockerfile_gate, make_effective_user_trigger, exec_context, image, test_context
):
    effective_user_trigger = make_effective_user_trigger(test_context["trigger_params"])

    dockerfile_gate.prepare_context(image, exec_context)
    assert effective_user_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert effective_user_trigger.did_fire
        assert len(effective_user_trigger.fired) == 1
        assert effective_user_trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert effective_user_trigger.did_fire is False


# exposed ports parameterized via dicts
# Tests in order: port in blacklist, port no in blacklist, port in whitelist, port not in whitelist
exposed_ports_test_contexts = [
    {
        "trigger_params": {"ports": "2800,3000", "type": "blacklist"},
        "expected_fire": True,
        "expected_msg": "Dockerfile exposes port (3000) which is in policy file DENIEDPORTS list",
    },
    {
        "trigger_params": {"ports": "2800", "type": "blacklist"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"ports": "3000", "type": "whitelist"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"ports": "2800,3001", "type": "whitelist"},
        "expected_fire": True,
        "expected_msg": "Dockerfile exposes port (3000) which is not in policy file ALLOWEDPORTS list",
    },
]


@pytest.mark.parametrize("test_context", exposed_ports_test_contexts)
def test_exposed_ports_trigger(
    dockerfile_gate, make_exposed_ports_trigger, exec_context, image, test_context
):
    exposed_ports_trigger = make_exposed_ports_trigger(test_context["trigger_params"])

    dockerfile_gate.prepare_context(image, exec_context)
    assert exposed_ports_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert exposed_ports_trigger.did_fire
        assert len(exposed_ports_trigger.fired) == 1
        assert exposed_ports_trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert exposed_ports_trigger.did_fire is False


instruction_check_test_contexts = [
    {
        "trigger_params": {"instruction": "COPY", "check": "=", "value": ". /app"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check '=' matched against '. /app' for line '. /app'",
    },
    {
        "trigger_params": {"instruction": "COPY", "check": "!=", "value": ". /app"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"instruction": "COPY", "check": "exists"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'exists' matched against '' for line '. /app'",
    },
    {
        "trigger_params": {"instruction": "VOLUME", "check": "not_exists"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'VOLUME' not found, matching condition 'not_exists' check",
    },
    {
        "trigger_params": {"instruction": "COPY", "check": "not_exists"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"instruction": "COPY", "check": "like", "value": ". /"},
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'like' matched against '. /' for line '. /app'",
    },
    {
        "trigger_params": {
            "instruction": "COPY",
            "check": "like",
            "value": ". /usr/local/bin",
        },
        "expected_fire": False,
    },
    {
        "trigger_params": {
            "instruction": "COPY",
            "check": "not_like",
            "value": ". /usr",
        },
        "expected_fire": True,
        "expected_msg": "Dockerfile directive 'COPY' check 'not_like' matched against '. /usr' for line '. /app'",
    },
    {
        "trigger_params": {
            "instruction": "COPY",
            "check": "not_like",
            "value": ". /app",
        },
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", instruction_check_test_contexts)
def test_instruction_check_trigger(
    dockerfile_gate, make_instruction_check_trigger, exec_context, image, test_context
):
    instruction_check_trigger = make_instruction_check_trigger(
        test_context["trigger_params"]
    )

    dockerfile_gate.prepare_context(image, exec_context)
    assert instruction_check_trigger.execute(image, exec_context)

    if test_context["expected_fire"]:
        assert instruction_check_trigger.did_fire
        assert len(instruction_check_trigger.fired) == 1
        assert instruction_check_trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert instruction_check_trigger.did_fire is False


actual_dockerfile_only_test_contexts = [
    {
        "trigger_type": "instruction_check",
        "trigger_params": {"instruction": "COPY", "check": "exists"},
    },
    {
        "trigger_type": "exposed_port",
        "trigger_params": {"ports": "3000", "type": "blacklist"},
    },
]


@pytest.mark.parametrize("test_context", actual_dockerfile_only_test_contexts)
def test_actual_dockerfile_only(
    dockerfile_gate,
    exec_context,
    image,
    test_context,
    make_actual_dockerfile_only_trigger,
):
    image.dockerfile_mode = None

    trigger = make_actual_dockerfile_only_trigger(
        test_context["trigger_type"], test_context["trigger_params"]
    )

    dockerfile_gate.prepare_context(image, exec_context)
    assert trigger.execute(image, exec_context)
    assert not trigger.did_fire
