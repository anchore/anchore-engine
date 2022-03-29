import pytest

from anchore_engine.analyzers.syft.handlers.common import save_entry_to_findings


@pytest.mark.parametrize(
    "param",
    [
        pytest.param(
            {
                "findings": {"package_list": {"test": {"base": {}}}},
                "entry": {
                    "unit": "testvalue",
                },
                "pkg_type": "test",
                "pkg_key": "key_test",
                "expected": {"unit": "testvalue"},
            },
            id="basic-case",
        ),
        pytest.param(
            {
                "findings": {
                    "package_list": {
                        "test": {"base": {"key_test": {"unit2": "testvalue2"}}}
                    }
                },
                "entry": {
                    "unit": "testvalue",
                },
                "pkg_type": "test",
                "pkg_key": "key_test",
                "expected": {"unit2": "testvalue2"},
            },
            id="no-overwrite",
        ),
        pytest.param(
            {
                "findings": {},
                "entry": {
                    "unit": "testvalue",
                },
                "pkg_type": "test",
                "pkg_key": "key_test",
                "expected": {"unit": "testvalue"},
            },
            id="keyerror",
        ),
    ],
)
def test_save_entry_to_findings(param):
    findings = param["findings"]
    save_entry_to_findings(
        findings, param["entry"], param["pkg_type"], param["pkg_key"]
    )
    assert (
        findings.get("package_list", {})
        .get(param["pkg_type"], {})
        .get("base", {})
        .get(param["pkg_key"], {})
        == param["expected"]
    )
