from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.check_suidfiles import SuidDiffTrigger, SuidFileAddTrigger, SuidFileDelTrigger, SuidModeDiffTrigger, SuidDiffGate


class SuidDiffGateTest(GateUnitTest):
    gate_clazz = SuidDiffGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_suiddifftrigger(self):
        t, gate, test_context = self.get_initialized_trigger(SuidDiffTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_suidaddtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(SuidFileAddTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_suiddeltrigger(self):
        t, gate, test_context = self.get_initialized_trigger(SuidFileDelTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_suidmodedifftrigger(self):
        t, gate, test_context = self.get_initialized_trigger(SuidModeDiffTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)
