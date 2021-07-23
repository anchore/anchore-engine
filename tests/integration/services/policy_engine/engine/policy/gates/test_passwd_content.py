import pytest

from anchore_engine.db import Image, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.passwd_file import (
    FileNotStoredTrigger,
    FileparsePasswordGate,
    GroupIdMatchTrigger,
    PEntryMatchTrigger,
    ShellMatchTrigger,
    UserIdMatchTrigger,
    UsernameMatchTrigger,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()


@pytest.mark.usefixtures("cls_no_feeds_test_env")
class FileparsePasswordGateTest(GateUnitTest):
    gate_clazz = FileparsePasswordGate
    __default_image__ = "debian9-slim-custom"

    def test_filenotstored(self):
        db = get_thread_scoped_session()
        image = db.query(Image).get((self.test_env.get_images_named("node")[0][0], "0"))
        t, gate, test_context = self.get_initialized_trigger(
            FileNotStoredTrigger.__trigger_name__
        )
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            FileNotStoredTrigger.__trigger_name__
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(0, len(t.fired))
        db.rollback()

    def test_userblacklist(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            UsernameMatchTrigger.__trigger_name__, user_names="mail,news,foobar"
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        logger.info("Context: {}".format(test_context.data))
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(2, len(t.fired))
        db.rollback()

    def test_uidblacklist(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            UserIdMatchTrigger.__trigger_name__, user_ids="5,1000"
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_gidblacklist(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            GroupIdMatchTrigger.__trigger_name__, group_ids="1,1000"
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_shellblacklist(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            ShellMatchTrigger.__trigger_name__, shells="/bin/bash,/bin/ksh"
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

    def test_pentryblacklist(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            PEntryMatchTrigger.__trigger_name__,
            entry="mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()
