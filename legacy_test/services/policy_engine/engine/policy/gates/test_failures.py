import json
import unittest

from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, BundleExecution
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.gates.dockerfile import DockerfileGate, ExposedPortsTrigger
from anchore_engine.services.policy_engine.engine.policy.exceptions import TriggerEvaluationError, TriggerNotAvailableError, TriggerNotFoundError, ValidationError, PolicyRuleValidationErrorCollection

test_bundle = {
    'id': 'test_id',
    'name': 'TestEmptyBundle',
    'version': '1_0',
    'policies': [],
    'whitelists': [],
    'mappings': []
}


class FailTrigger(BaseTrigger):
    __description__ = 'Testing Trigger for ensuring failure'
    __trigger_name__ = 'FAILALWAYS'
    __msg__ = 'FAILALWAYS triggered'

    __params__ = {
        'PARAM1': str,
        'PARAM2': int
    }

    def evaluate(self, image_obj, context):
        raise Exception('Failing as intended')


class FailGate(Gate):
    __gate_name__ = 'FAILGATE'
    __triggers__ = [
        FailTrigger
    ]


class GateFailureTest(unittest.TestCase):
    gate_clazz = DockerfileGate

    def test_trigger_init_failure(self):
        with self.assertRaises(KeyError) as f:
            t = self.gate_clazz.get_trigger_named('NOT_A_REAL_TRIGGER')

        t = self.gate_clazz.get_trigger_named(ExposedPortsTrigger.__trigger_name__)

    def test_trigger_exec_failure(self):
        clazz = self.gate_clazz.get_trigger_named(ExposedPortsTrigger.__trigger_name__)
        trigger = clazz(self.gate_clazz, ports='8088', type='whitelist')
        with self.assertRaises(TriggerEvaluationError) as f:
            trigger.execute(image_obj=None, context=None)

    def test_trigger_parameter_invalid(self):
        clazz = self.gate_clazz.get_trigger_named(ExposedPortsTrigger.__trigger_name__)

        with self.assertRaises(PolicyRuleValidationErrorCollection) as f:
            trigger = clazz(self.gate_clazz, notaparam='testing123')

        with self.assertRaises(PolicyRuleValidationErrorCollection) as f:
            trigger = clazz(self.gate_clazz, allowed_ports='80')

    def test_trigger_parameter_validation_failure(self):
        clazz = self.gate_clazz.get_trigger_named(ExposedPortsTrigger.__trigger_name__)

        with self.assertRaises(PolicyRuleValidationErrorCollection) as f:
            trigger = clazz(self.gate_clazz, allowedports=80)

        with self.assertRaises(ValidationError) as f:
            trigger = clazz(self.gate_clazz, allowedports='80-100')

class PolicyFailureTest(unittest.TestCase):

    def test_bundle_failure(self):
        b = build_bundle(test_bundle)
        image_obj = Image(id='fakeid1')

        r = b.execute(image_object=image_obj, tag='dockerhub/library/alpine:latest', context=object())
        print((json.dumps((r.json()), indent=2)))


if __name__ == '__main__':
    unittest.main()