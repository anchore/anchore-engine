import unittest

from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.subsys import logger

logger.enable_test_logging()


class TriggerForTest(BaseTrigger):
    __description__ = "Testing trigger"
    __trigger_name__ = "testtrigger"
    __msg__ = "Some msg"


class GateForTesting(Gate):
    __description__ = "Testing gate"
    __gate_name__ = "testgate"
    __triggers__ = [TriggerForTest]


class TestGateTriggerNameMatches(unittest.TestCase):
    def test_gate_name_match(self):
        names = [
            "testgate",
            "TESTGATE",
            "testGate",
            "TestGate",
        ]

        failz = ["test gate", "TEST GATE"]

        for name in names:
            self.assertIsNotNone(Gate.get_gate_by_name(name))

        for name in failz:
            with self.assertRaises(Exception) as e:
                Gate.get_gate_by_name(name)

    def test_trigger_name_match(self):
        g = Gate.registry["testgate"]

        names = ["testtrigger", "testTrigger", "TESTTRIGGER"]

        failz = ["test trigger", "TEST TRIGGER"]

        for name in names:
            self.assertTrue(g.has_trigger(name))

        for name in failz:
            self.assertFalse(g.has_trigger(name))
