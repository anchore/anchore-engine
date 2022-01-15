import unittest

from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext


class GateUnitTest(unittest.TestCase):
    __default_image__ = "node"
    gate_clazz = None

    def get_initialized_trigger(self, trigger_name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(trigger_name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(
            db_session=get_thread_scoped_session(), configuration=config
        )
        gate = trigger.gate_cls()

        return trigger, gate, context
