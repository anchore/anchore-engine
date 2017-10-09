from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.pkg_diff import PkgDiffGate, PkgVersionDiffTrigger, PkgAddTrigger, PkgDelTrigger, PkgDiffTrigger
from anchore_engine.db import Image, get_thread_scoped_session
from test.services.policy_engine.engine.policy.gates import GateUnitTest, init_db

class PkgDiffGateTest(GateUnitTest):
    gate_clazz = PkgDiffGate

    @classmethod
    def setUpClass(cls):
        init_db(connect_str=cls.test_env.mk_db())
        db = get_thread_scoped_session()
        cls.test_image1 = db.query(Image).get((cls.test_env.get_images_named('testimage1')[0][0], '0'))
        cls.test_image2 = db.query(Image).get((cls.test_env.get_images_named('testimage2')[0][0], '0'))
        db.rollback()

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_pkgversiondiff(self):
        t, gate, test_context = self.get_initialized_trigger(PkgVersionDiffTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image1)
        test_context = gate.prepare_context(self.test_image1, test_context)
        t.evaluate(self.test_image1, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_pkgadd(self):
        t, gate, test_context = self.get_initialized_trigger(PkgAddTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image1)
        test_context = gate.prepare_context(self.test_image1, test_context)
        t.evaluate(self.test_image1, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreater(len(t.fired), 1)

        t.reset()
        db = get_thread_scoped_session()
        db.refresh(self.test_image2)
        test_context = gate.prepare_context(self.test_image2, test_context)
        t.evaluate(self.test_image2, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreaterEqual(len(t.fired), 2)

    def test_pkgdel(self):
        t, gate, test_context = self.get_initialized_trigger(PkgDelTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image1)
        test_context = gate.prepare_context(self.test_image1, test_context)
        t.evaluate(self.test_image1, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

    def test_pkgdiff(self):
        t, gate, test_context = self.get_initialized_trigger(PkgDiffTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image1)
        test_context = gate.prepare_context(self.test_image1, test_context)
        t.evaluate(self.test_image1, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
