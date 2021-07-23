import pytest

from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.retrieved_files import (
    FileContentRegexMatchTrigger,
    RetrievedFileChecksGate,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()


@pytest.mark.usefixtures("cls_no_feeds_test_env")
class RetrievedFiledGateTest(GateUnitTest):
    gate_clazz = RetrievedFileChecksGate
    __default_image__ = "debian9-slim-custom"

    def test_regex_match_trigger(self):
        db = get_thread_scoped_session()
        t, gate, test_context = self.get_initialized_trigger(
            FileContentRegexMatchTrigger.__trigger_name__,
            path="/etc/passwd",
            regex=".*root.*",
            check="match",
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()

        t, gate, test_context = self.get_initialized_trigger(
            FileContentRegexMatchTrigger.__trigger_name__,
            path="/etc/passwd",
            regex=".*foobar.*",
            check="no_match",
        )
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))
        db.rollback()
