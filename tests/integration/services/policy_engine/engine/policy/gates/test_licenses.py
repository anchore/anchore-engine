import pytest

from anchore_engine.db import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.licenses import (
    FullMatchTrigger,
    LicensesGate,
    SubstringMatchTrigger,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()


@pytest.mark.usefixtures("cls_no_feeds_test_env")
class LicenseBlacklistGateTest(GateUnitTest):
    gate_clazz = LicensesGate

    def test_fullmatch(self):
        t, gate, test_context = self.get_initialized_trigger(
            FullMatchTrigger.__trigger_name__, licenses="Apache-2.0"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(len(t.fired), 1)

    def test_namematch(self):
        t, gate, test_context = self.get_initialized_trigger(
            SubstringMatchTrigger.__trigger_name__, licenses="GPL"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(len(t.fired), 1)
