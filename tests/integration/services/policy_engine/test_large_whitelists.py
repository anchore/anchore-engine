"""
Test for the indexing/optimizations for handling large whitelists (>100 rules)
"""

import json
import time

import pytest

from anchore_engine.db import Image
from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.services.policy_engine.engine.policy.bundles import (
    ExecutableWhitelist,
    build_bundle,
)
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.subsys import logger

logger.enable_test_logging()


def test_basic_whitelist_evaluation(bundle, test_data_env_with_images_loaded):
    default_bundle = bundle()
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/node:latest"
    built = build_bundle(default_bundle, for_tag=test_tag)
    assert not built.init_errors
    logger.info(("Got: {}".format(built)))

    db = get_session()
    img_obj = db.query(Image).get(
        (test_data_env_with_images_loaded.get_images_named("node")[0][0], "0")
    )

    assert img_obj is not None, "Failed to get an image object to test"
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None, "Got None eval"
    logger.info((json.dumps(evaluation.json(), indent=2)))
    logger.info((json.dumps(evaluation.as_table_json(), indent=2)))


def test_whitelists(bundle, test_data_env_with_images_loaded):
    default_bundle = bundle()
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/node:latest"

    [x for x in default_bundle["whitelists"] if x["id"] == "wl_jessie"][0][
        "items"
    ].append(
        {"gate": "vulnerabilities", "trigger_id": "*binutils*", "id": "testinserted123"}
    )
    built = build_bundle(default_bundle, for_tag=test_tag)
    assert not built.init_errors
    logger.info(("Got: {}".format(built)))

    db = get_session()
    img_obj = db.query(Image).get(
        (test_data_env_with_images_loaded.get_images_named("node")[0][0], "0")
    )
    assert img_obj is not None
    t = time.time()
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    assert evaluation is not None
    logger.info(("Evaluation: {}".format(json.dumps(evaluation.json(), indent=2))))
    logger.info(("Took: {}".format(time.time() - t)))

    # Run without index handlers
    logger.info("Running without optimized indexes")
    ExecutableWhitelist._use_indexes = False
    no_index_built = build_bundle(default_bundle, for_tag=test_tag)
    assert not no_index_built.init_errors
    logger.info(("Got: {}".format(no_index_built)))

    t = time.time()
    no_index_evaluation = no_index_built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )

    ExecutableWhitelist._use_indexes = True

    assert (
        evaluation.json() == no_index_evaluation.json()
    ), "Index vs non-indexed returned different results"
    assert no_index_evaluation is not None, "Got None eval"
    logger.info(
        ("Non-indexed Evaluation: {}".format(json.dumps(evaluation.json(), indent=2)))
    )
    logger.info(("Non-indexed Evaluation Took: {}".format(time.time() - t)))


@pytest.mark.skip(
    "Need to update the logic here to be non-CVE dependent or lock the cve matches to make it reliable"
)
def test_regexes(bundle, test_data_env_with_images_loaded):
    """
    Test regular expressions in the trigger_id part of the WL rule
    :return:
    """
    bundle = bundle()
    logger.info("Building executable bundle from default bundle")
    test_tag = "docker.io/library/node:latest"

    node_whitelist = [x for x in bundle["whitelists"] if x["id"] == "wl_jessie"][0]
    node_whitelist["items"] = [
        x for x in node_whitelist["items"] if "binutils" in x["trigger_id"]
    ]
    node_whitelist["items"].append(
        {
            "gate": "vulnerabilities",
            "trigger_id": "CVE-2016-6515+openssh-client",
            "id": "testinserted3",
        }
    )
    node_whitelist["items"].append(
        {
            "gate": "vulnerabilities",
            "trigger_id": "CVE-2016-6515+*",
            "id": "test-cve-2016-6515",
        }
    )
    node_whitelist["items"].append(
        {"gate": "vulnerabilities", "trigger_id": "CVE-2017*", "id": "testinserted2"}
    )
    node_whitelist["items"].append(
        {"gate": "vulnerabilities", "trigger_id": "*binutils*", "id": "testinserted1"}
    )

    db = get_session()
    img_obj = db.query(Image).get(
        (test_data_env_with_images_loaded.get_images_named("node")[0][0], "0")
    )
    assert img_obj is not None

    ExecutableWhitelist._use_indexes = True
    built = build_bundle(bundle, for_tag=test_tag)
    assert not built.init_errors

    logger.info("Executing with indexes")
    t = time.time()
    evaluation = built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    t1 = time.time() - t
    logger.info(("Took: {}".format(t1)))
    assert evaluation is not None

    ExecutableWhitelist._use_indexes = False
    non_index_built = build_bundle(bundle, for_tag=test_tag)
    assert not non_index_built.init_errors
    logger.info("Executing without indexes")
    t2 = time.time()
    evaluation2 = non_index_built.execute(
        img_obj, tag=test_tag, context=ExecutionContext(db_session=db, configuration={})
    )
    t2 = time.time() - t2
    logger.info(("Took: {}".format(t2)))
    assert evaluation2 is not None
    ExecutableWhitelist._use_indexes = True

    assert (
        evaluation.json()["bundle_decision"]["policy_decisions"][0]["decisions"]
        == evaluation2.json()["bundle_decision"]["policy_decisions"][0]["decisions"]
    )
    logger.info(("Evaluation: {}".format(json.dumps(evaluation.json(), indent=2))))
    open_ssl_wl_match = {
        "action": "go",
        "rule": {
            "action": "stop",
            "gate": "vulnerabilities",
            "trigger": "package",
            "params": {},
        },
        "match": {
            "message": "HIGH Vulnerability found in package - openssh-client (CVE-2016-6515 - https://security-tracker.debian.org/tracker/CVE-2016-6515)",
            "trigger": "package",
            "whitelisted": {
                "whitelist_id": "wl_jessie",
                "matched_rule_id": "testinserted3",
                "whitelist_name": "CVE whitelist for jessie - 12092017",
            },
            "trigger_id": "CVE-2016-6515+openssh-client",
        },
    }
    assert (
        open_ssl_wl_match
        in evaluation.json()["bundle_decision"]["policy_decisions"][0]["decisions"]
    )
    assert (
        len(
            [
                x
                for x in evaluation.json()["bundle_decision"]["policy_decisions"][0][
                    "decisions"
                ]
                if x["match"].get("whitelisted", {}).get("matched_rule_id", "")
                in ["testinserted1", "testinserted2", "testinserted3"]
            ]
        )
        >= 1
    )
