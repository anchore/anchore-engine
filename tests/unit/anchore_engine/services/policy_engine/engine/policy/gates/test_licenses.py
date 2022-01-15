import pytest

from anchore_engine.db.entities.policy_engine import Image, ImagePackage
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates import licenses

image_id = "1"
user = "admin"


@pytest.fixture()
def packages():
    return [
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="git",
            license="GPL-2 LGPL-2.1+ EDL-1.0 GPL-2+ Expat BSD-2-clause GPL-1+ ISC mingw-runtime Boost dlmalloc Apache-2.0 LGPL-2+",
        ),
        ImagePackage(
            image_id=image_id,
            image_user_id=user,
            name="gnupg",
            license="GPL-3+ permissive LGPL-2.1+ Expat LGPL-3+ RFC-Reference TinySCHEME BSD-3-clause",
        ),
    ]


@pytest.fixture()
def image(packages):
    return Image(id="image_id", user_id="user", packages=packages)


@pytest.fixture()
def licenses_gate():
    return licenses.LicensesGate()


@pytest.fixture()
def exec_context():
    return ExecutionContext(db_session=None, configuration={})


def base_trigger_assertions(trigger, test_context):
    if test_context["expected_fire"]:
        assert trigger.did_fire
        assert len(trigger.fired) == 1
        assert trigger.fired[0].msg == test_context["expected_msg"]
    else:
        assert not trigger.did_fire
        assert len(trigger.fired) == 0

    return True


full_match_test_contexts = [
    {
        "licenses": "BSD-2-clause",
        "expected_fire": True,
        "expected_msg": "LICFULLMATCH Packages are installed that have blacklisted licenses: git(BSD-2-clause)",
    },
    {
        "licenses": "BSD-2-clause,Boost",
        "expected_fire": True,
        "expected_msg": "LICFULLMATCH Packages are installed that have blacklisted licenses: git(BSD-2-clause), git(Boost)",
    },
    {
        "licenses": "BSD-3-clause,Boost",
        "expected_fire": True,
        "expected_msg": "LICFULLMATCH Packages are installed that have blacklisted licenses: git(Boost), gnupg(BSD-3-clause)",
    },
    {
        "licenses": "LGPL-2.1+",
        "expected_fire": True,
        "expected_msg": "LICFULLMATCH Packages are installed that have blacklisted licenses: git(LGPL-2.1+), gnupg(LGPL-2.1+)",
    },
    {
        "licenses": "no-match",
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", full_match_test_contexts)
def test_full_match_trigger(licenses_gate, exec_context, image, test_context):
    full_match_trigger = licenses.FullMatchTrigger(
        parent_gate_cls=licenses_gate.__class__, licenses=test_context["licenses"]
    )

    licenses_gate.prepare_context(image, exec_context)

    assert full_match_trigger.execute(image, exec_context)

    assert base_trigger_assertions(full_match_trigger, test_context)


substring_match_test_contexts = [
    {
        "licenses": "RFC",
        "expected_fire": True,
        "expected_msg": "LICSUBMATCH Packages are installed that have blacklisted licenses: gnupg(RFC-Reference)",
    },
    {
        "licenses": "LGPL",
        "expected_fire": True,
        "expected_msg": "LICSUBMATCH Packages are installed that have blacklisted licenses: git(LGPL-2.1+), git(LGPL-2+), gnupg(LGPL-2.1+), gnupg(LGPL-3+)",
    },
    {
        "licenses": "GNU",
        "expected_fire": False,
    },
]


@pytest.mark.parametrize("test_context", substring_match_test_contexts)
def test_substring_match_trigger(licenses_gate, exec_context, image, test_context):
    substring_match_trigger = licenses.SubstringMatchTrigger(
        parent_gate_cls=licenses_gate.__class__, licenses=test_context["licenses"]
    )

    licenses_gate.prepare_context(image, exec_context)

    assert substring_match_trigger.execute(image, exec_context)

    assert base_trigger_assertions(substring_match_trigger, test_context)
