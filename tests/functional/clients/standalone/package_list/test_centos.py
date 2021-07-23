import pytest

from . import path_params
from .fixtures import centos


class TestRpm:
    @pytest.mark.parametrize("path", path_params(centos.pkgfiles_all))
    def test_pkgfiles_all(self, analyzed_data, path):
        result = analyzed_data("rpm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgfiles.all"
        ]["base"]
        assert pkgs.get(path) == "RPMFILE"

    @pytest.mark.parametrize(
        "pkg,version",
        [
            pytest.param(pkg, version, id=pkg)
            for pkg, version in centos.pkgs_all.items()
        ],
    )
    def test_pkgs_all(self, analyzed_data, pkg, version):
        result = analyzed_data("rpm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.all"
        ]["base"]
        assert pkgs.get(pkg) == version

    @pytest.mark.parametrize("pkg,metadata", centos.pkgs_allinfo.items())
    def test_pkgs_allinfo(self, analyzed_data, pkg, metadata):
        result = analyzed_data("rpm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        loaded = pkgs.get(pkg, {})
        assert loaded == metadata
