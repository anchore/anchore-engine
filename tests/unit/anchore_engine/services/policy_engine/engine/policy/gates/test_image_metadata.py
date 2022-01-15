import pytest

from anchore_engine.db.entities.policy_engine import Image
from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    PolicyRuleValidationErrorCollection,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import image_metadata

image_id = "1"
user = "admin"


@pytest.fixture()
def image():
    return Image(
        id=image_id,
        user_id="user",
        size=141455360,
        distro_name="debian",
        distro_version="10",
        like_distro="debian",
        docker_data_json={
            "Architecture": "amd64",
            "RepoDigests": [
                "docker.io/library/nginx@sha256:34f3f875e745861ff8a37552ed7eb4b673544d2c56c7cc58f9a9bec5b4b3530e"
            ],
            "RepoTags": ["docker.io/library/nginx:latest"],
        },
        layers_json=[
            "sha256:bb79b6b2107fea8e8a47133a660b78e3a546998fcf0427be39ac9a0af4a97e90",
            "sha256:5a9f1c0027a73bc0e66a469f90e47a59e23ab3472126ed28e6a4e7b1a98d1eb5",
            "sha256:b5c20b2b484f5ca9bc9d98dc79f8f1381ee0c063111ea0ddf42d1ae5ea942d50",
            "sha256:166a2418f7e86fa48d87bf6807b4e5b35f078acb2ad1cbf10444a7025913c24f",
            "sha256:1966ea362d2394e7c5c508ebf3695f039dd3825bd1e7a07449ae530aea3c4cd1",
        ],
    )


@pytest.fixture()
def image_metadata_gate():
    return image_metadata.ImageMetadataGate()


@pytest.fixture()
def make_image_metadata_attribute_check_trigger(image_metadata_gate):
    def _make_image_metadata_attribute_check_trigger(params):
        return image_metadata.ImageMetadataAttributeCheckTrigger(
            parent_gate_cls=image_metadata_gate.__class__, **params
        )

    return _make_image_metadata_attribute_check_trigger


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


image_metadata_attribute_contexts = [
    {
        "trigger_params": {"attribute": "size", "check": ">", "value": "0"},
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'size' check: '>' check_value: '0' matched image value: '141455360'",
    },
    {
        "trigger_params": {"attribute": "size", "check": "<", "value": "100000000"},
        "expected_fire": False,
    },
    {
        "trigger_params": {
            "attribute": "architecture",
            "check": "like",
            "value": "amd64",
        },
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'architecture' check: 'like' check_value: 'amd64' matched image value: 'amd64'",
    },
    {
        "trigger_params": {
            "attribute": "architecture",
            "check": "not_like",
            "value": "amd64",
        },
        "expected_fire": False,
    },
    {
        "trigger_params": {"attribute": "os_type", "check": "not_exists", "value": ""},
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'os_type' check: 'not_exists' check_value: '' matched image value: 'None'",
    },
    {
        "trigger_params": {
            "attribute": "distro",
            "check": "in",
            "value": "debian,centos",
        },
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'distro' check: 'in' check_value: 'debian,centos' matched image value: 'debian'",
    },
    {
        "trigger_params": {
            "attribute": "distro",
            "check": "not_in",
            "value": "debian,centos",
        },
        "expected_fire": False,
    },
    {
        "trigger_params": {"attribute": "distro_version", "check": "=", "value": "10"},
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'distro_version' check: '=' check_value: '10' matched image value: '10'",
    },
    {
        "trigger_params": {"attribute": "distro_version", "check": "!=", "value": "10"},
        "expected_fire": False,
    },
    {
        "trigger_params": {"attribute": "like_distro", "check": "exists", "value": ""},
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'like_distro' check: 'exists' check_value: '' matched image value: 'debian'",
    },
    {
        "trigger_params": {"attribute": "layer_count", "check": ">=", "value": "5"},
        "expected_fire": True,
        "expected_msg": "Attribute check for attribute: 'layer_count' check: '>=' check_value: '5' matched image value: '5'",
    },
    {
        "trigger_params": {"attribute": "layer_count", "check": ">", "value": "5"},
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", image_metadata_attribute_contexts)
def test_image_metadata_attribute_check_trigger(
    image_metadata_gate,
    make_image_metadata_attribute_check_trigger,
    image,
    exec_context,
    test_context,
):
    attribute_check_trigger = make_image_metadata_attribute_check_trigger(
        test_context["trigger_params"]
    )

    image_metadata_gate.prepare_context(image, exec_context)

    assert attribute_check_trigger.execute(image, exec_context)
    if test_context["expected_fire"]:
        assert attribute_check_trigger.did_fire
        assert len(attribute_check_trigger.fired) == 1
        assert attribute_check_trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert not attribute_check_trigger.did_fire


invalid_rule_params = [
    {"attribute": "foo", "check": ">", "value": "200"},
    {"attribute": "size", "check": "!", "value": "200"},
    {"attribute": "size", "check": "!=", "value": "test"},
    {"attribute": "size", "check": "!=", "value": 32},
]


@pytest.mark.parametrize("trigger_params", invalid_rule_params)
def test_invalid_rule_check(
    image_metadata_gate,
    make_image_metadata_attribute_check_trigger,
    image,
    exec_context,
    trigger_params,
):
    with pytest.raises(PolicyRuleValidationErrorCollection):
        make_image_metadata_attribute_check_trigger(trigger_params)
