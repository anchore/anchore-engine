from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import FileparsePasswordGate
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import FileNotStoredTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import UsernameMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import UserIdMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import GroupIdMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import ShellMatchTrigger
from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.fileparse_passwd import PEntryMatchTrigger


class FileparsePasswordGateTest(GateUnitTest):
    gate_clazz = FileparsePasswordGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

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
        t, gate, test_context = self.get_initialized_trigger(UsernameMatchTrigger.__trigger_name__, usernameblacklist='mail,ftp,foobar')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(2, len(t.fired))
        db.rollback()

    def test_uidblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(UserIdMatchTrigger.__trigger_name__, useridblacklist='5,100')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_gidblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(GroupIdMatchTrigger.__trigger_name__, groupidblacklist='100,10000')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_shellblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(ShellMatchTrigger.__trigger_name__, shellblacklist='/bin/bash,/bin/ksh')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_pentryblacklist(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named('centos7_verify')[0][0], '0'))
        t, gate, test_context = self.get_initialized_trigger(PEntryMatchTrigger.__trigger_name__, pentryblacklist='mail:x:8:12:mail:/var/spool/mail:/sbin/nologin')
        db.refresh(self.test_image)
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        print(('Fired: {}'.format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()
