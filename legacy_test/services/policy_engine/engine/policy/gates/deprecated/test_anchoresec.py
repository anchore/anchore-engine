from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.anchoresec import AnchoreSecGate, \
    UnsupportedDistroTrigger, \
    FeedOutOfDateTrigger, \
    HighSeverityTrigger, \
    MediumSeverityTrigger, \
    LowSeverityTrigger, \
    UnknownSeverityTrigger, \
    CriticalSeverityTrigger

from anchore_engine.db import Image, get_thread_scoped_session
from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest


class AnchoreSecGateTest(GateUnitTest):
    gate_clazz = AnchoreSecGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_unsupported_distro(self):
        t, gate, test_context = self.get_initialized_trigger(UnsupportedDistroTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('busybox')[0][0], '0'))
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)

    def test_feedoutofdate(self):
        t, gate, test_context = self.get_initialized_trigger(FeedOutOfDateTrigger.__trigger_name__, maxage="0")
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(FeedOutOfDateTrigger.__trigger_name__, maxage="1000000")
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 0)

    def test_highseverity(self):
        t, gate, test_context = self.get_initialized_trigger(HighSeverityTrigger.__trigger_name__)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_criticalseverity(self):
        t, gate, test_context = self.get_initialized_trigger(CriticalSeverityTrigger.__trigger_name__)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

    def test_mediumseverity(self):
        t, gate, test_context = self.get_initialized_trigger(MediumSeverityTrigger.__trigger_name__)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_lowseverity(self):
        t, gate, test_context = self.get_initialized_trigger(LowSeverityTrigger.__trigger_name__)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_unknownsverity(self):
        t, gate, test_context = self.get_initialized_trigger(UnknownSeverityTrigger.__trigger_name__)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_fixavailableparam(self):
        t, gate, test_context = self.get_initialized_trigger(UnknownSeverityTrigger.__trigger_name__, fix_available='True')
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(UnknownSeverityTrigger.__trigger_name__, fix_available='False')
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)






