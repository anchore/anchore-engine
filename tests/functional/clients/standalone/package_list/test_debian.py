import pytest

from . import path_params
from .fixtures import debian


class TestDebianPaths:
    @pytest.mark.parametrize("path", path_params(debian.pkgfiles_all))
    def test_pkgfiles_all(self, analyzed_data, path):
        result = analyzed_data("stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgfiles.all"
        ]["base"]
        assert pkgs.get(path) == "DPKGFILE"

    @pytest.mark.parametrize(
        "pkg,version",
        [
            pytest.param(pkg, version, id=pkg)
            for pkg, version in debian.pkgs_all.items()
        ],
    )
    def test_pkgs_all(self, analyzed_data, pkg, version):
        result = analyzed_data("stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.all"
        ]["base"]
        assert pkgs.get(pkg) == version

    @pytest.mark.parametrize("pkg,metadata", debian.pkgs_allinfo.items())
    def test_pkgs_allinfo(self, analyzed_data, pkg, metadata):
        result = analyzed_data("stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        loaded = pkgs.get(pkg, {})

        # a separate test exists just for the licenses attribute, leave this out of the assertion
        loaded = dict(loaded)
        loaded.pop("license")
        metadata = dict(metadata)
        metadata.pop("license")

        assert loaded == metadata

    @pytest.mark.parametrize("pkg,metadata", debian.pkgs_allinfo.items())
    def test_pkgs_allinfo_license(self, analyzed_data, pkg, metadata):
        result = analyzed_data("stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        loaded = pkgs.get(pkg, {})
        actual = set(loaded["license"].split(" "))
        expected = set(metadata["license"].split(" "))
        assert actual == expected

    @pytest.mark.parametrize(
        "pkg,version",
        [
            pytest.param(pkg, version, id=pkg)
            for pkg, version in debian.pkgs_all.items()
        ],
    )
    def test_pkgs_plus_source_all(self, analyzed_data, pkg, version):
        result = analyzed_data("stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs_plus_source.all"
        ]["base"]
        assert pkgs.get(pkg) == version
