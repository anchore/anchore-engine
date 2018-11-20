from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import FileparsePasswordGate
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import FileNotStoredTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import UsernameMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import UserIdMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import GroupIdMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import ShellMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import PEntryMatchTrigger


class FileparsePasswordGateTest(GateUnitTest):
    gate_clazz = FileparsePasswordGate

    def test_filenotstored(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(FileNotStoredTrigger.__trigger_name__)
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(0, len(t.fired))
        db.rollback()

        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(FileNotStoredTrigger.__trigger_name__)
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_userblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(UsernameMatchTrigger.__trigger_name__, user_names='mail,ftp,foobar')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(2, len(t.fired))
        db.rollback()

    def test_uidblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(UserIdMatchTrigger.__trigger_name__, user_ids='5,100')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_gidblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(GroupIdMatchTrigger.__trigger_name__, group_ids='100,10000')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_shellblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(ShellMatchTrigger.__trigger_name__, shells='/bin/bash,/bin/ksh')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_pentryblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(PEntryMatchTrigger.__trigger_name__, entry='mail:x:8:12:mail:/var/spool/mail:/sbin/nologin')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()
