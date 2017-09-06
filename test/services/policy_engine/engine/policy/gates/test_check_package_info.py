from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.check_package_info import PackageCheckGate, PkgNotPresentTrigger
from anchore_engine.db import get_thread_scoped_session


class PackageCheckGateTest(GateUnitTest):
    gate_clazz = PackageCheckGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_pkgnotpresentdiff(self):
        t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, PKGFULLMATCH='binutils|2.25-5+deb8u1,libssl|123')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, PKGNAMEMATCH='binutilityrepo,binutils')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, PKGVERSMATCH='binutils|2.25-5+deb8u1,randopackage|123,binutils|3.25-5+deb8u1')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 2)

        t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, PKGFULLMATCH='binutils|2.25-5+deb8u1,libssl|123', PKGNAMEMATCH='binutils,foobar', PKGVERSMATCH='binutils|2.25-5+deb8u1,libssl|10.2,blamo|123.123')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 4)
