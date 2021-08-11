import copy
import json
import os

import pytest

from anchore_engine.analyzers.manager import apply_hints

# Used to determine which path in findings should be accessed
hint_file_pkg_type_map = {
    "alpine_hints.json": "pkgs.allinfo",
    "debian_hints.json": "pkgs.allinfo",
    "rpm_hints.json": "pkgs.allinfo",
    "gem_hints.json": "pkgs.gems",
    "java_hints.json": "pkgs.java",
    "npm_hints.json": "pkgs.npms",
    "python_hints.json": "pkgs.python",
}
distro_hint_files = ["alpine_hints.json", "debian_hints.json", "rpm_hints.json"]


class TestApplyHints:
    @pytest.fixture
    def module_path(self, request):
        """
        Gets the path for current file
        """
        return os.path.dirname(request.module.__file__)

    @pytest.fixture
    def analyzer_report(self, module_path):
        """
        Reads and returns the analyzer report in this directory. Has every type of package in it
        """
        f = open(os.path.join(module_path, "analyzer_report.json"))
        return json.load(f)

    @pytest.fixture
    def hints_dirpath(self, module_path):
        """
        Directory path of hints files
        """
        return os.path.join(module_path, "mock_hints_files")

    @pytest.fixture
    def patch_hints_read(self, monkeypatch):
        """
        Factory that patches the function that reads from the hints file.
        Will change it to return the object passed to the factory
        """

        def _patch_read(hints):
            def _hints(**kwargs):
                return hints

            monkeypatch.setattr("anchore_engine.analyzers.utils.get_hintsfile", _hints)

        return _patch_read

    @pytest.fixture
    def get_hints(self, hints_dirpath):
        """
        Reads the hints file with name passed to function. Handles path to directory. All it needs is filename
        """

        def _get_hints(filename):
            f = open(os.path.join(hints_dirpath, filename))
            return json.load(f)

        return _get_hints

    @pytest.mark.parametrize("hints_filename", hint_file_pkg_type_map.keys())
    def test_hints_defines_path(self, hints_filename, patch_hints_read, get_hints):
        # There was a bug that was causing issues when syft did not process a certain type of artifact that was then
        # processed as a hint. Certain paths of nested attributes were being accessed without being defined
        # This test is designed to ensure that each handler can set the attributes it needs when hints are applied
        analyzer_report = {}
        pkg_type = hint_file_pkg_type_map[hints_filename]
        hints = get_hints(hints_filename)
        patch_hints_read(hints)

        apply_hints(analyzer_report, "")

        applied_hints = analyzer_report["package_list"][pkg_type]["base"]
        assert len(applied_hints) == len(hints["packages"])

        # if distro hints verify the package. Non distro types have more complicated key verification
        for pkg in hints["packages"]:
            if hints_filename in distro_hint_files:
                assert pkg["name"] in analyzer_report["package_list"][pkg_type]["base"]
            else:
                assert (
                    pkg["location"] in analyzer_report["package_list"][pkg_type]["base"]
                )

    def test_no_override_existing_entry(self, patch_hints_read, get_hints, caplog):
        # Hints should not overwrite any existing entries. This tests that it logs the issue and does not change it
        hints = get_hints("debian_hints.json")
        patch_hints_read(hints)

        analyzer_report = {
            "package_list": {
                "pkgs.allinfo": {
                    "base": {
                        "tzdata": {
                            "type": "dpkg",
                            "name": "tzdata",
                            "version": "test-no-override",
                            "origin": "",
                            "license": "",
                            "arch": "noarch",
                            "release": "N/A",
                            "sourcepkg": "tzdata-2021a-1.fc34",
                            "size": "0",
                        },
                    }
                }
            }
        }

        apply_hints(analyzer_report, "")

        assert "package already present under" in caplog.text
        assert (
            analyzer_report["package_list"]["pkgs.allinfo"]["base"]["tzdata"]["version"]
            == "test-no-override"
        )

    @pytest.mark.parametrize("hints_filename", hint_file_pkg_type_map.keys())
    def test_merge(self, hints_filename, get_hints, analyzer_report, patch_hints_read):
        # Verifies that the merge works as intended and does not overwrite or remove existing entries in the report
        # Does this by using an analysis report with a single entry for each pkg type
        # Gets the before state, applies hints, and verifies that new data is present along with old
        hints = get_hints(hints_filename)
        patch_hints_read(hints)
        hints_pkg_type = hint_file_pkg_type_map[hints_filename]
        report_pre_hints = copy.deepcopy(analyzer_report)

        apply_hints(analyzer_report, "")

        # verify identical pkg types
        assert set(report_pre_hints["package_list"].keys()) == set(
            analyzer_report["package_list"].keys()
        )

        # loop over each package type to verify the content is as expected
        for pkg_type in report_pre_hints["package_list"].keys():
            pre_hints = report_pre_hints["package_list"][pkg_type]["base"]
            post_hints = analyzer_report["package_list"][pkg_type]["base"]

            # If the same type as the hints applied verify original data is present along with new
            if pkg_type == hints_pkg_type:
                assert len(post_hints) == len(pre_hints) + len(hints["packages"])
                for pkg_key in pre_hints.keys():
                    assert post_hints[pkg_key] == pre_hints[pkg_key]
            # else it should not have changed and should be an exact match
            else:
                assert pre_hints == post_hints
