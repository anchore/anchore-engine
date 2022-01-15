import pytest

from anchore_engine.services.policy_engine.engine.policy.gates import (
    PackageCheckGate,
    BaseTrigger,
)
from anchore_engine.services.policy_engine.engine.policy.gates.dockerfile import (
    EffectiveUserTrigger,
)
from anchore_engine.services.policy_engine.engine.policy.gates.npms import (
    PkgMatchTrigger,
)
from anchore_engine.services.policy_engine.engine.policy.params import (
    CommaDelimitedStringListParameter,
    EnumStringParameter,
    TriggerParameter,
)


class TestBaseTrigger:

    """
    For the purposes of this test, we are using a few random trigger and gate (instead of testing every gate/trigger class combo)
    To verify the parameters method works well.

    This is specific to the random trigger that was selected, essentially verifying that
    the parameters method does what it's supposed to, which is retrieving a dict of
    data attributes and their values.

    Note: for the gate parameter it is crucial to use a gate that has __lifecycle_state__ == LifecycleStates.eol for this test.
    Otherwise, the BaseTrigger constructor won't be able to execute because the parameter validation will fail
    """

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "trigger": EffectiveUserTrigger,
                    "gate": PackageCheckGate,
                    "expected_params": {
                        "user": CommaDelimitedStringListParameter,
                        "allowed_type": EnumStringParameter,
                    },
                },
                id="effective-user-trigger",
            ),
            pytest.param(
                {
                    "trigger": PkgMatchTrigger,
                    "gate": PackageCheckGate,
                    "expected_params": {
                        "name": TriggerParameter,
                        "version": TriggerParameter,
                    },
                },
                id="npm-pkg-match-trigger",
            ),
        ],
    )
    def test_parameters(self, param):
        parameters = param["trigger"](param["gate"]).parameters()
        for key, value in param["expected_params"].items():
            assert parameters.get(key).__class__ == value

    def test_reset(self):
        trigger = BaseTrigger(PackageCheckGate)
        trigger._fired_instances = [1, 2, 3]
        trigger.reset()
        assert trigger._fired_instances == []
