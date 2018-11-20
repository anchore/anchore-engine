from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image
from anchore_engine.services.policy_engine.engine.policy.gates.npms import NpmCheckGate, NotOfficialTrigger, NotLatestTrigger, NoFeedTrigger, BadVersionTrigger, PkgMatchTrigger


class NpmCheckGateTest(GateUnitTest):
    gate_clazz = NpmCheckGate

    def test_notofficial(self):
        t, gate, test_context = self.get_initialized_trigger(NotOfficialTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

    def test_notlatest(self):
        t, gate, test_context = self.get_initialized_trigger(NotLatestTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

    def test_nofeed(self):
        t, gate, test_context = self.get_initialized_trigger(NoFeedTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 0)


    def test_badversion(self):
        t, gate, test_context = self.get_initialized_trigger(BadVersionTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

    def test_pkgfullmatch(self):
        t, gate, test_context = self.get_initialized_trigger(PkgMatchTrigger.__trigger_name__, name='abbrev', version='1.1.0')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

        t, gate, test_context = self.get_initialized_trigger(PkgMatchTrigger.__trigger_name__, name='ajv', version='4.11.8')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

