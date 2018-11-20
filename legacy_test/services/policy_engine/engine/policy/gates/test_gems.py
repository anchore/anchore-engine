from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image

from anchore_engine.services.policy_engine.engine.policy.gates.gems import GemCheckGate, NotOfficialTrigger, NotLatestTrigger, NoFeedTrigger, BadVersionTrigger, BlacklistedGemTrigger


class GemCheckGateTest(GateUnitTest):
    gate_clazz = GemCheckGate
    
    def setUp(self):
        db = get_thread_scoped_session()
        self.test_image = db.query(Image).get((self.test_env.get_images_named('ruby')[0][0], '0'))


    def test_notofficial(self):
        t, gate, test_context = self.get_initialized_trigger(NotOfficialTrigger.__trigger_name__, )
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
        t, gate, test_context = self.get_initialized_trigger(BlacklistedGemTrigger.__trigger_name__, name='json', version='2.0.2')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(BlacklistedGemTrigger.__trigger_name__, name='jsonify',
                                                             version='2.0.2')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

        t, gate, test_context = self.get_initialized_trigger(BlacklistedGemTrigger.__trigger_name__, name='json',
                                                             version='2.0.1')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)

    def test_pkgnamematch(self):
        t, gate, test_context = self.get_initialized_trigger(BlacklistedGemTrigger.__trigger_name__, name='json')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(BlacklistedGemTrigger.__trigger_name__, name='blah')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertGreaterEqual(len(t.fired), 0)
