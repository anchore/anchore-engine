from datetime import datetime
from typing import List
from anchore_engine.services.policy_engine.api import util
from anchore_engine.services.policy_engine.api.models import Tag, Image
from anchore_engine.services.policy_engine.api.models import (
    PolicyRule,
    PolicyRuleParams,
)


def test_deserialize_image():
    dikt = {
        "id": "1",
        "digest": "111",
        "user_id": "1",
        "state": "initializing",
        "distro_namespace": "namespace",
        "created_at": str(datetime.now()),
        "last_modified": str(datetime.now()),
        "tags": ["tag1", "tag2"],
    }

    result = util.deserialize_model(dikt, Image)
    assert isinstance(result, Image)


class TestPolicyRule:
    def test_with_params(self):
        policy_rule_params = [
            {"name": "rule1", "value": "value1"},
            {"name": "rule2", "value": "value2"},
        ]

        dikt = {
            "id": "1",
            "gate": "1",
            "trigger": "trigger",
            "action": "GO",
            "params": policy_rule_params,
        }
        result = util.deserialize_model(dikt, PolicyRule)
        assert result.id == "1"
        assert len(result.params) == 2
