import unittest

from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.db import Image, ImagePackageManifestEntry
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.check_package_info import PackageCheckGate, PkgNotPresentTrigger, VerifyTrigger
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

    def test_pkgnotpresentdiff(self):
        db = get_thread_scoped_session()
        try:
            image = db.query(Image).get((self.test_env.get_images_named('node')[0][0], '0'))
            t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, pkgfullmatch='binutils|2.25-5+deb8u1,libssl|123')
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            print(('Fired: {}'.format(t.fired)))
            self.assertEqual(len(t.fired), 1)

            t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, pkgnamematch='binutilityrepo,binutils')
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            print(('Fired: {}'.format(t.fired)))
            self.assertEqual(len(t.fired), 1)

            t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, pkgversmatch='binutils|2.25-5+deb8u1,randopackage|123,binutils|3.25-5+deb8u1')
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            print(('Fired: {}'.format(t.fired)))
            self.assertEqual(len(t.fired), 2)

            t, gate, test_context = self.get_initialized_trigger(PkgNotPresentTrigger.__trigger_name__, pkgfullmatch='binutils|2.25-5+deb8u1,libssl|123', pkgnamematch='binutils,foobar', pkgversmatch='binutils|2.25-5+deb8u1,libssl|10.2,blamo|123.123')
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            print(('Fired: {}'.format(t.fired)))
            self.assertEqual(len(t.fired), 4)
        finally:
            db.rollback()

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
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 2)
        self.assertTrue(('missing' in t.fired[0].msg and 'changed' in t.fired[1].msg) or ('missing' in t.fired[1].msg and 'changed' in t.fired[0].msg))

        print('Specific dirs and check only changed')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, dirs='/bin,/usr/bin,/usr/local/bin,/usr/share/locale', check_only='changed')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('changed' in t.fired[0].msg)

        print('Check only missing')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, check_only='missing')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('missing' in t.fired[0].msg)

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, pkgs='perl-base,libapt-pkg5.0,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 2)
        self.assertTrue(('missing' in t.fired[0].msg and 'changed' in t.fired[1].msg) or ('missing' in t.fired[1].msg and 'changed' in t.fired[0].msg))

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, pkgs='perl-base,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('missing' in t.fired[0].msg)

        print('Specific pkg, with issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, pkgs='libapt-pkg5.0,tzdata')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 1)
        self.assertTrue('changed' in t.fired[0].msg)

        print('Specific pkg, no issues')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__, pkgs='tzdata,openssl-client')
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(len(t.fired), 0)

        print('Trying default params on all loaded images')
        t, gate, test_context = self.get_initialized_trigger(VerifyTrigger.__trigger_name__)
        for img_id, meta in list(self.test_env.image_map.items()):
            if img_id == self.test_image.id:
                continue
            t.reset()

            img_obj = db.query(Image).get((img_id, '0'))
            print(('Default params check on img: {}'.format(img_id)))

            test_context = gate.prepare_context(img_obj, test_context)
            t.evaluate(img_obj, test_context)
            print(('Image name: {}, id: {}, Fired count: {}\nFired: {}'.format(meta.get('name'), img_id, len(t.fired), t.fired)))
            #self.assertEqual(len(t.fired), 0, 'Found failed verfications on: {}'.format(img_obj.id))

    def test_db_pkg_compare(self):
        """
        Test the pkg metadata diff function specifically.

        :return:
        """
        int_m = int('010755', 8)
        p1 = ImagePackageManifestEntry()
        p1.file_path = '/test1'
        p1.is_config_file = False
        p1.size = 1000
        p1.mode = int_m
        p1.digest = 'abc'
        p1.digest_algorithm = 'sha256'

        fs_entry = {
            'is_packaged': True,
            'name': '/test1',
            'suid': None,
            'entry_type': 'file',
            'linkdst_fullpath': None,
            'mode': int_m,
            'othernames': [],
            'sha256_checksum': 'abc',
            'md5_checksum': 'def',
            'sha1_checksum': 'abcdef',
            'size': 1000
        }

        # Result == False
        # Basic equal eval
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        p1.digest = None
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest = 'abc'

        # Is config file, skip comparison since expected to change
        p1.is_config_file = True
        p1.digest = 'blah123'
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.is_config_file = False
        p1.digest = 'abc'

        # sha1 diffs
        p1.digest_algorithm = 'sha1'
        p1.digest = 'abcdef'
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest_algorithm = 'sha256'
        p1.digest = 'abc'

        # Cannot compare due to missing digest types
        p1.digest_algorithm = 'sha1'
        f = fs_entry.pop('sha1_checksum')
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest_algorithm = 'sha256'
        fs_entry['sha1_checksum'] = f

        # Result == Changed

        # Mode diffs
        p1.mode = int_m + 1
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.mode = int_m

        # Size diffs
        p1.size = 1001
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.size = 1000

        # Sha256 diffs
        p1.digest = 'abd'
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # md5 diffs
        p1.digest_algorithm = 'md5'
        p1.digest = 'blah'
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # sha1 diffs
        p1.digest_algorithm = 'sha1'
        p1.digest = 'blah'
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        p1.digest = 'abc'
        p1.digest_algorithm = 'sha256'

        # Some weird mode checks to ensure different length mode numbers are ok
        # FS longer than pkg_db, but eq in match
        fs_entry['mode'] = int('060755', 8)
        p1.mode = int('0755', 8)
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # FS longer than pkg_db but not eq
        fs_entry['mode'] = int('060754', 8)
        p1.mode = int('0755', 8)
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # FS shorter than pkg_db and match
        fs_entry['mode'] = int('0755', 8)
        p1.mode = int('060755', 8)
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # FS shorter than pkg_db and no match
        fs_entry['mode'] = int('0755', 8)
        p1.mode = int('060754', 8)
        self.assertEqual(VerifyTrigger.VerificationStates.changed, VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # Result == missing

        # Check against no entry
        self.assertEqual(VerifyTrigger.VerificationStates.missing, VerifyTrigger._diff_pkg_meta_and_file(p1, None))

        # Check against empty entry
        self.assertEqual(VerifyTrigger.VerificationStates.missing, VerifyTrigger._diff_pkg_meta_and_file(p1, {}))

