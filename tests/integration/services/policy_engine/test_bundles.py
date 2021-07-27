import copy
import json

import pytest

from anchore_engine.db import Image, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.bundles import (
    GateAction,
    build_bundle,
)
from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    BundleTargetTagMismatchError,
    InitializationError,
    UnsupportedVersionError,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.subsys import logger

logger.enable_test_logging()


def get_image_named(db, test_env, name):
    img_obj = (
        db.query(Image)
        .filter_by(id=test_env.get_images_named(name)[0][0], user_id="0")
        .one_or_none()
    )
    return img_obj


def test_basic_evaluation(test_data_env_with_images_loaded):
    db = get_thread_scoped_session()
    logger.info("Session state: {}".format(db.__dict__))
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    test_bundle = test_data_env_with_images_loaded.get_bundle("multitest")
    built = build_bundle(test_bundle, for_tag=test_tag)
    assert not built.init_errors
    logger.info("Got: {}".format(built))

    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info("Native json: {}\n".format(json.dumps(evaluation.json(), indent=2)))
    logger.info(
        "Table json: {}\n".format(json.dumps(evaluation.as_table_json(), indent=2))
    )

    # Diff old an new defaults
    multi_bundle = test_data_env_with_images_loaded.get_bundle("multi_default")
    multi_default = build_bundle(multi_bundle, for_tag=test_tag)
    assert not built.init_errors
    logger.info("Got: {}".format(multi_default))
    assert img_obj is not None, "Failed to get an image object to test"
    multi_default_evaluation = multi_default.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    default_built = build_bundle(
        test_data_env_with_images_loaded.get_bundle("default"), for_tag=test_tag
    )
    assert not built.init_errors
    logger.info("Got: {}".format(default_built))
    assert img_obj is not None, "Failed to get an image object to test"
    default_evaluation = default_built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert (
        multi_default_evaluation.as_table_json() == default_evaluation.as_table_json()
    )


def test_basic_legacy_evaluation(test_data_env_with_images_loaded):
    db = get_thread_scoped_session()
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    built = build_bundle(
        test_data_env_with_images_loaded.get_bundle("default"), for_tag=test_tag
    )
    assert not built.init_errors
    logger.info("Got: {}".format(built))

    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info(json.dumps(evaluation.json(), indent=2))
    logger.info(json.dumps(evaluation.as_table_json(), indent=2))


def test_duplicate_rule_evaluation(test_data_env_with_images_loaded):
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    multi_gate_bundle = {
        "id": "multigate1",
        "name": "Multigate test1",
        "version": "1_0",
        "policies": [
            {
                "id": "policy1",
                "name": "Test policy1",
                "version": "1_0",
                "rules": [
                    {
                        "gate": "always",
                        "trigger": "always",
                        "params": [],
                        "action": "GO",
                    },
                    {
                        "gate": "always",
                        "trigger": "always",
                        "params": [],
                        "action": "STOP",
                    },
                    {
                        "action": "stop",
                        "gate": "dockerfile",
                        "trigger": "instruction",
                        "params": [
                            {"name": "instruction", "value": "RUN"},
                            {"name": "check", "value": "exists"},
                        ],
                    },
                    {
                        "action": "STOP",
                        "gate": "dockerfile",
                        "trigger": "instruction",
                        "params": [
                            {"name": "instruction", "value": "USER"},
                            {"name": "CHECK", "value": "not_exists"},
                        ],
                    },
                    {
                        "action": "STOP",
                        "gate": "dockerfile",
                        "trigger": "instruction",
                        "params": [
                            {"name": "instruction", "value": "RUN"},
                            {
                                "name": "CHECK",
                                "value": "=",
                                "check_value": "yum update -y",
                            },
                        ],
                    },
                ],
            }
        ],
        "whitelists": [],
        "mappings": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "*"},
                "policy_id": "policy1",
                "whitelist_ids": [],
            }
        ],
    }
    built = build_bundle(multi_gate_bundle, for_tag=test_tag)
    assert not built.init_errors
    logger.info("Got: {}".format(built))

    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info(json.dumps(evaluation.json(), indent=2))
    logger.info(json.dumps(evaluation.as_table_json(), indent=2))


def test_image_whitelist(test_data_env_with_images_loaded):
    bundle = {
        "id": "multigate1",
        "name": "Multigate test1",
        "version": "1_0",
        "policies": [
            {
                "id": "policy1",
                "name": "Test policy1",
                "version": "1_0",
                "rules": [
                    {
                        "gate": "always",
                        "trigger": "always",
                        "params": [],
                        "action": "STOP",
                    }
                ],
            }
        ],
        "whitelists": [],
        "mappings": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "*"},
                "policy_id": "policy1",
                "whitelist_ids": [],
            }
        ],
        "whitelisted_images": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "latest"},
            }
        ],
        "blacklisted_images": [],
    }
    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    test_tag = "docker.io/library/ruby:alpine"
    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.stop == evaluation.bundle_decision.final_decision
    assert "policy_evaluation" == evaluation.bundle_decision.reason

    assert img_obj is not None, "Failed to get an image object to test"
    test_tag = "docker.io/library/ruby:latest"
    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.go == evaluation.bundle_decision.final_decision
    assert "whitelisted" == evaluation.bundle_decision.reason


def test_image_blacklist(test_data_env_with_images_loaded):
    bundle = {
        "id": "multigate1",
        "name": "Multigate test1",
        "version": "1_0",
        "policies": [
            {
                "id": "policy1",
                "name": "Test policy1",
                "version": "1_0",
                "rules": [
                    {
                        "gate": "always",
                        "trigger": "always",
                        "params": [],
                        "action": "STOP",
                    }
                ],
            }
        ],
        "whitelists": [],
        "mappings": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "*"},
                "policy_id": "policy1",
                "whitelist_ids": [],
            }
        ],
        "blacklisted_images": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "latest"},
            }
        ],
        "whitelisted_images": [],
    }

    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    test_tag = "docker.io/library/ruby:alpine"
    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.stop == evaluation.bundle_decision.final_decision
    assert "policy_evaluation" == evaluation.bundle_decision.reason

    assert img_obj is not None, "Failed to get an image object to test"
    test_tag = "docker.io/library/ruby:latest"
    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.stop == evaluation.bundle_decision.final_decision
    assert "blacklisted" == evaluation.bundle_decision.reason

    bundle = {
        "id": "emptytest1",
        "name": "Empty mapping test1",
        "version": "1_0",
        "policies": [],
        "whitelists": [],
        "mappings": [],
        "blacklisted_images": [
            {"registry": "*", "repository": "*", "image": {"type": "tag", "value": "*"}}
        ],
        "whitelisted_images": [],
    }

    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.stop == evaluation.bundle_decision.final_decision
    assert "blacklisted" == evaluation.bundle_decision.reason

    bundle = {
        "id": "emptytest1",
        "name": "Empty mapping test1",
        "version": "1_0",
        "policies": [],
        "whitelists": [],
        "mappings": [],
        "whitelisted_images": [
            {"registry": "*", "repository": "*", "image": {"type": "tag", "value": "*"}}
        ],
        "blacklisted_images": [],
    }

    built = build_bundle(bundle, for_tag=test_tag)
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    assert GateAction.go == evaluation.bundle_decision.final_decision
    assert "whitelisted" == evaluation.bundle_decision.reason


def test_whitelists(test_data_env_with_images_loaded):
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    built = build_bundle(
        test_data_env_with_images_loaded.get_bundle("default"), for_tag=test_tag
    )
    assert not built.init_errors
    logger.info("Got: {}".format(built))
    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info(json.dumps(evaluation.json(), indent=2))
    logger.info(json.dumps(evaluation.as_table_json(), indent=2))

    to_whitelist = evaluation.bundle_decision.policy_decisions[0].decisions[0]
    whitelist_bundle = copy.deepcopy(
        test_data_env_with_images_loaded.get_bundle("default")
    )
    whitelist_bundle["whitelists"].append(
        {
            "id": "generated_whitelist1",
            "name": "test_whitelist",
            "version": "1_0",
            "items": [
                {
                    "gate": to_whitelist.match.trigger.gate_cls.__gate_name__,
                    "trigger_id": to_whitelist.match.id,
                    "id": "test_whitelistitem",
                }
            ],
        }
    )

    whitelist_bundle["mappings"][0]["whitelist_ids"] = ["generated_whitelist1"]
    built = build_bundle(whitelist_bundle, for_tag=test_tag)

    logger.info("Got updated: {}".format(built))

    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    assert img_obj is not None
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None
    # logger.info(json.dumps(evaluation.json(), indent=2))
    # logger.info(json.dumps(evaluation.as_table_json(), indent=2))

    assert to_whitelist.match.id not in [
        x.match.id
        if not (hasattr(x.match, "is_whitelisted") and x.match.is_whitelisted)
        else None
        for x in evaluation.bundle_decision.policy_decisions[0].decisions
    ]


def test_error_evaluation(test_data_env_with_images_loaded):
    bundle = {
        "id": "someid",
        "version": "1_0",
        "whitelists": [],
        "policies": [],
        "mappings": [],
    }

    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    built = build_bundle(bundle, for_tag=test_tag)
    logger.info("Got: {}".format(built))

    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    assert evaluation is not None
    logger.info("Result: {}".format(json.dumps(evaluation.as_table_json(), indent=2)))

    with pytest.raises(BundleTargetTagMismatchError) as f:
        evaluation = built.execute(
            img_obj,
            tag="docker.io/library/ubuntu:vivid-2015",
            context=ExecutionContext(db_session=db, configuration={}),
        )


def test_deprecated_gate_evaluation_error(test_data_env_with_images_loaded):
    """
    Test the policy build of deprecated gates with deprecated explicitly disallowed
    :return:
    """
    bundle = {
        "id": "someid",
        "version": "1_0",
        "whitelists": [],
        "policies": [
            {
                "id": "abc",
                "name": "Deprecated Policy",
                "version": "1_0",
                "rules": [
                    {
                        "gate": "PKGDIFF",
                        "trigger": "pkgadd",
                        "params": [],
                        "action": "stop",
                    },
                    {
                        "gate": "always",
                        "trigger": "always",
                        "action": "go",
                        "params": [],
                    },
                    {
                        "gate": "ANCHORESEC",
                        "trigger": "VULNLOW",
                        "action": "warn",
                        "params": [],
                    },
                ],
            }
        ],
        "mappings": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "*"},
                "name": "Default",
                "policy_id": "abc",
                "whitelist_ids": [],
            }
        ],
    }

    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    db = get_thread_scoped_session()
    with pytest.raises(InitializationError) as ex:
        built = build_bundle(bundle, for_tag=test_tag, allow_deprecated=False)
        logger.info("Got: {}".format(built))

        img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
        assert img_obj is not None, "Failed to get an image object to test"

        evaluation = built.execute(
            img_obj,
            tag=test_tag,
            context=ExecutionContext(db_session=db, configuration={}),
        )


@pytest.mark.skip
def testDeprecatedGateEvaluationOk(test_data_env_with_images_loaded):
    """
    Test the policy build with deprecated explicitly allowed.
    :return:
    """

    bundle = {
        "id": "someid",
        "version": "1_0",
        "whitelists": [],
        "policies": [
            {
                "id": "abc",
                "name": "Deprecated Policy",
                "version": "1_0",
                "rules": [
                    {
                        "gate": "PKGDIFF",
                        "trigger": "pkgadd",
                        "params": [],
                        "action": "stop",
                    },
                    {
                        "gate": "always",
                        "trigger": "always",
                        "action": "go",
                        "params": [],
                    },
                    {
                        "gate": "ANCHORESEC",
                        "trigger": "VULNLOW",
                        "action": "warn",
                        "params": [],
                    },
                ],
            }
        ],
        "mappings": [
            {
                "registry": "*",
                "repository": "*",
                "image": {"type": "tag", "value": "*"},
                "name": "Default",
                "policy_id": "abc",
                "whitelist_ids": [],
            }
        ],
    }

    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/ruby:latest"
    db = get_thread_scoped_session()

    built = build_bundle(bundle, for_tag=test_tag, allow_deprecated=True)
    logger.info("Got: {}".format(built))

    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info("Result: {}".format(json.dumps(evaluation.json(), indent=2)))
    assert evaluation.warnings is not None


def test_policy_init_error(test_data_env_with_images_loaded):
    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")

    ruby_tag = "dockerhub/library/ruby:latest"

    with pytest.raises(UnsupportedVersionError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "invalid_version",
                "name": "invalid_version",
                "whitelists": [],
                "policies": [],
                "mappings": [],
            }
        )
        built.execute(image_object=img_obj, context=None, tag=ruby_tag)

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "invalid_version",
                        "name": "bad whitelist",
                        "rules": [],
                    }
                ],
                "policies": [
                    {
                        "id": "ok_policy",
                        "version": "v1.0",
                        "name": "bad policy",
                        "rules": [],
                    }
                ],
                "mappings": [
                    {
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                        "policy_id": "ok_policy",
                        "whitelist_ids": ["whitelist1"],
                    }
                ],
            },
            for_tag="dockerhub/library/centos:latest",
        )
        built.execute(
            image_object=img_obj, context=None, tag="dockerhub/library/centos:latest"
        )

    assert type(f.value.causes[0]) == UnsupportedVersionError

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "okwhitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "invalid_policy",
                        "version": "invalid_version",
                        "name": "bad policy",
                        "rules": [],
                    }
                ],
                "mappings": [
                    {
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                        "policy_id": "invalid_policy",
                        "whitelist_ids": ["whitelist1"],
                    }
                ],
            },
            for_tag="dockerhub/library/centos:latest",
        )
        built.execute(
            image_object=img_obj, context=None, tag="dockerhub/library/centos:latest"
        )
    assert type(f.value.causes[0]) == UnsupportedVersionError

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "2_0",
                        "name": "ok policy",
                        "rules": [],
                    }
                ],
                "mappings": [
                    {
                        "id": "invalid_mapping",
                        "policy_id": "okpolicy",
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=img_obj, context=None, tag=ruby_tag)
    assert type(f.value.causes[0]) == UnsupportedVersionError


def test_multi_policy_missing_errors(test_data_env_with_images_loaded):
    """
    Test entries in policy_ids that are not found in bundle

    :return:
    """

    ruby_tag = "dockerhub/library/ruby:latest"

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "testbundle",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                ],
                "mappings": [
                    {
                        "id": "invalid_mapping",
                        "policy_ids": ["okpolicy", "okpolicy2", "notrealpolicy"],
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )

        built.execute(image_object=Image(), context=None, tag=ruby_tag)


def test_multi_policy_invalid_errors(test_data_env_with_images_loaded):
    """
    Test validation of policies in multi-policy mapping
    :return:
    """

    ruby_tag = "dockerhub/library/ruby:latest"

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                    {
                        "id": "okpolicy",
                        "version": "2_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                ],
                "mappings": [
                    {
                        "id": "ok_mapping",
                        "policy_ids": ["okpolicy", "okpolicy2"],
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=Image(), context=None, tag=ruby_tag)


def test_multi_policy_mix_use_errors(test_data_env_with_images_loaded):
    """
    Test validation of policies in multi-policy mapping
    :return:
    """

    ruby_tag = "dockerhub/library/ruby:latest"

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                ],
                "mappings": [
                    {
                        "id": "invalid_mapping",
                        "policy_id": "notrealpolicy",
                        "policy_ids": ["okpolicy", "okpolicy2"],
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=Image(), context=None, tag=ruby_tag)

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                    {
                        "id": "okpolicy",
                        "version": "2_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                ],
                "mappings": [
                    {
                        "id": "invalid_mapping",
                        "policy_id": "okpolicy2",
                        "policy_ids": ["okpolicy"],
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=Image(), context=None, tag=ruby_tag)


@pytest.mark.skip
def test_no_policy_in_mapping_errors(test_data_env_with_images_loaded):
    """
    Test validation of policies in multi-policy mapping
    :return:
    """

    ruby_tag = "dockerhub/library/ruby:latest"

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_version",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [],
                    },
                ],
                "mappings": [
                    {
                        "id": "invalid_mapping",
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=Image(), context=None, tag=ruby_tag)


def test_policy_not_found(test_data_env_with_images_loaded):
    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            test_data_env_with_images_loaded.get_bundle("bad_policy_id")
        )
        built.execute(
            image_object=img_obj, context=None, tag="dockerhub/library/ruby:latest"
        )
        logger.info("Expected Initialization error: {}".format(f.exception))


def test_invalid_actions(test_data_env_with_images_loaded):
    db = get_thread_scoped_session()
    img_obj = get_image_named(db, test_data_env_with_images_loaded, "ruby")
    assert img_obj is not None

    with pytest.raises(InitializationError) as f:
        built = build_bundle(test_data_env_with_images_loaded.get_bundle("bad_bundle1"))
        built.execute(
            image_object=img_obj, context=None, tag="dockerhub/library/ruby:latest"
        )
        built.execute(image_object=img_obj, context=None, tag="test")

    with pytest.raises(InitializationError) as f:
        built = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_actions",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [
                            {
                                "gate": "always",
                                "trigger": "always",
                                "action": "HELLO",
                                "params": [],
                            }
                        ],
                    }
                ],
                "mappings": [
                    {
                        "policy_id": "okpolicy",
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=img_obj, context=None, tag=None)

    with pytest.raises(InitializationError) as f:
        bad_param1 = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_params",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [
                            {
                                "gate": "vulnerabilities",
                                "trigger": "stale_feed_data",
                                "action": "GO",
                                "params": [
                                    {"name": "max_days_since_sync", "value": 0.1}
                                ],
                            }
                        ],
                    }
                ],
                "mappings": [
                    {
                        "policy_id": "okpolicy",
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=img_obj, context=None, tag=None)

    with pytest.raises(InitializationError) as f:
        bad_param2 = build_bundle(
            {
                "id": "someid",
                "version": "1_0",
                "name": "invalid_params",
                "whitelists": [
                    {
                        "id": "whitelist1",
                        "version": "1_0",
                        "name": "ok whitelist",
                        "items": [],
                    }
                ],
                "policies": [
                    {
                        "id": "okpolicy",
                        "version": "1_0",
                        "name": "ok policy",
                        "rules": [
                            {
                                "gate": "vulnerabilities",
                                "trigger": "stale_feed_data",
                                "action": "GO",
                                "params": [
                                    {"name": "max_days_since_sync", "value": 10}
                                ],
                            }
                        ],
                    }
                ],
                "mappings": [
                    {
                        "policy_id": "okpolicy",
                        "whitelist_ids": ["whitelist1"],
                        "registry": "*",
                        "repository": "*",
                        "image": {"type": "tag", "value": "*"},
                    }
                ],
            }
        )
        built.execute(image_object=img_obj, context=None, tag=None)
