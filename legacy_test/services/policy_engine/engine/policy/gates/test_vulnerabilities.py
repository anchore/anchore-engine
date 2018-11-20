from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.vulnerabilities import VulnerabilitiesGate, \
    UnsupportedDistroTrigger, \
    FeedOutOfDateTrigger, \
    VulnerabilityMatchTrigger

from anchore_engine.db import Image, get_thread_scoped_session
from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest


class AnchoreSecGateTest(GateUnitTest):
    gate_clazz = VulnerabilitiesGate

    def test_unsupported_distro(self):
        t, gate, test_context = self.get_initialized_trigger(UnsupportedDistroTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('busybox')[0][0], '0'))
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)

    def test_feedoutofdate(self):
        t, gate, test_context = self.get_initialized_trigger(FeedOutOfDateTrigger.__trigger_name__, max_days_since_sync="0")
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(FeedOutOfDateTrigger.__trigger_name__, max_days_since_sync="1000000")
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 0)

    def test_packages_severity(self):
        t, gate, test_context = self.get_initialized_trigger(VulnerabilityMatchTrigger.__trigger_name__, package_type='all', severity='medium', severity_comparison='>=')
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_fixavailableparam(self):
        t, gate, test_context = self.get_initialized_trigger(VulnerabilityMatchTrigger.__trigger_name__, package_type='all', severity='medium', severity_comparison='>=', fix_available='True')
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(VulnerabilityMatchTrigger.__trigger_name__, fix_available='False', severity='medium', severity_comparison='>', package_type='all')
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)






