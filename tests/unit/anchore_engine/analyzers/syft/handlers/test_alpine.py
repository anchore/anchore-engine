import pytest

from anchore_engine.analyzers.syft.handlers.alpine import save_entry, _all_packages


class TestAlpine:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test"},
                    "pkg_key": "basic-test",
                    "expected": {"name": "test"},
                    "expected_key": "basic-test",
                },
                id="basic-case",
            ),
            pytest.param(
                {
                    "findings": {},
                    "engine_entry": {"name": "test"},
                    "pkg_key": None,
                    "expected": {"name": "test"},
                    "expected_key": "test",
                },
                id="no-pkgkey-case",
            ),
        ],
    )
    def test_save_entry(self, param):
        findings = param["findings"]
        save_entry(findings, param["engine_entry"], param["pkg_key"])
        findings_key = param["expected_key"]
        assert (
            findings.get("package_list", {})
            .get("pkgs.allinfo", {})
            .get("base", {})
            .get(findings_key, {})
            == param["expected"]
        )

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "expected_key": "test",
                    "expected_version": "1.0.0",
                    "expected_err": None,
                    "artifact": {"name": "test", "version": "1.0.0"},
                },
                id="basic-success",
            ),
            pytest.param(
                {"expected_err": KeyError, "artifact": {"version": "1.0.0"}},
                id="missing-name",
            ),
            pytest.param(
                {"expected_err": KeyError, "artifact": {"name": "test"}},
                id="missing-version",
            ),
        ],
    )
    def test_all_packages(self, param):
        findings = {"package_list": {"pkgs.all": {"base": {}}}}
        if param["expected_err"] is not None:
            with pytest.raises(param["expected_err"]):
                _all_packages(findings, param["artifact"])
        else:
            _all_packages(findings, param["artifact"])
            assert (
                findings["package_list"]["pkgs.all"]["base"][param["expected_key"]]
                == param["expected_version"]
            )
