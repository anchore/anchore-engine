import pytest

from anchore_engine.db.entities.policy_engine import Image
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import always

image_id = "1"
user = "admin"


@pytest.fixture()
def image():
    return Image(id=image_id, user_id=user)


@pytest.fixture()
def always_gate():
    return always.AlwaysGate()


@pytest.fixture()
def always_fire_trigger(always_gate):
    return always.AlwaysFireTrigger(parent_gate_cls=always_gate.__class__)


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


def test_always_fire_trigger(always_gate, always_fire_trigger, exec_context, image):
    always_gate.prepare_context(image, exec_context)

    assert always_fire_trigger.execute(image, exec_context)
    assert always_fire_trigger.did_fire
    assert len(always_fire_trigger.fired) == 1
    assert always_fire_trigger.fired[0].id == "always"
    assert always_fire_trigger.fired[0].msg == always.AlwaysFireTrigger.__msg__
