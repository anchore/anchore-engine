import pytest

from . import path_params
from .fixtures import alpine


class TestAlpinePaths:
    @pytest.mark.parametrize("path", path_params(alpine.pkgfiles_all))
    def test_pkgfiles_all(self, analyzed_data, path):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgfiles.all"
        ]["base"]
        assert pkgs.get(path) == "APKFILE"

    @pytest.mark.parametrize(
        "pkg,version",
        [
            pytest.param(pkg, version, id=pkg)
            for pkg, version in alpine.pkgs_all.items()
        ],
    )
    def test_pkgs_all(self, analyzed_data, pkg, version):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.all"
        ]["base"]
        assert pkgs.get(pkg) == version

    @pytest.mark.parametrize("pkg,metadata", alpine.pkgs_allinfo.items())
    def test_pkgs_allinfo(self, analyzed_data, pkg, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        loaded = dict(pkgs.get(pkg, {}))

        # a separate test exists just for the files attribute, leave this out of the assertion
        loaded = dict(loaded)
        loaded.pop("files")
        metadata = dict(metadata)
        metadata.pop("files")

        assert loaded == metadata

    @pytest.mark.parametrize("pkg,metadata", alpine.pkgs_allinfo.items())
    def test_pkgs_allinfo_files(self, analyzed_data, pkg, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        loaded = pkgs.get(pkg, {})
        assert sorted(loaded["files"]) == sorted(metadata["files"])

    @pytest.mark.parametrize(
        "pkg,version",
        [
            pytest.param(pkg, version, id=pkg)
            for pkg, version in alpine.pkgs_plus_source_all.items()
        ],
    )
    def test_pkgs_plus_source_all(self, analyzed_data, pkg, version):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs_plus_source.all"
        ]["base"]
        assert pkgs.get(pkg) == version
