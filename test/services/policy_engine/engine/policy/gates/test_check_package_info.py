import unittest

from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.check_package_info import PackageCheckGate, PkgNotPresentTrigger, VerifyTrigger
from anchore_engine.db import get_thread_scoped_session


class PackageCheckGateTest(GateUnitTest):
    __default_image__ = 'debian' # Testing against a specifically broken analysis output (hand edited to fail in predictable ways)
    gate_clazz = PackageCheckGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    @unittest.skip('Test only verify')
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

    def test_verifytrigger(self):
        """
        Expects the default image to have exactly 1 verify file changed and 1 missing. For the debian test used that is in:
        /usr/share/locale/ for the missing entry and changed file (first entries in the verify analyzer output for the latest debian image at the test time

        :return:
        """

        print('Default params check')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 2)
        self.assertTrue(('missing' in t.fired[0].msg and 'changed' in t.fired[1].msg) or ('missing' in t.fired[1].msg and 'changed' in t.fired[0].msg))

        print('Specific dirs and check only changed')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, DIRS='/bin,/usr/bin,/usr/local/bin,/usr/share/locale', CHECK_ONLY='changed')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('changed' in t.fired[0].msg)

        print('Check only missing')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, CHECK_ONLY='missing')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('missing' in t.fired[0].msg)

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, PKGS='perl-base,libapt-pkg5.0,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 2)
        self.assertTrue(('missing' in t.fired[0].msg and 'changed' in t.fired[1].msg) or ('missing' in t.fired[1].msg and 'changed' in t.fired[0].msg))

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, PKGS='perl-base,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('missing' in t.fired[0].msg)

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, PKGS='libapt-pkg5.0,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('changed' in t.fired[0].msg)

        print('Specific pkg, no issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, PKGS='tzdata,openssl-client')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertEqual(len(t.fired), 0)

        print('Trying default params on all loaded images')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__)
        for img_id, meta in self.test_env.image_map.items():
            if img_id == self.test_image.id:
                continue
            t.reset()

            img_obj = db.query(Image).get((img_id, '0'))
            print('Default params check on img: {}'.format(img_id))

            test_context = gate.prepare_context(img_obj, test_context)
            t.evaluate(img_obj, test_context)
            print('Image name: {}, id: {}, Fired count: {}\nFired: {}'.format(meta.get('name'), img_id, len(t.fired), t.fired))
            #self.assertEqual(len(t.fired), 0, 'Found failed verfications on: {}'.format(img_obj.id))



