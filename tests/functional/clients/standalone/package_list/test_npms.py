# from ['image']['imagedata']['analysis_report']['package_list']
import pytest

from . import metadata_params, path_params
from .fixtures import npms


class TestJSPaths:
    @pytest.mark.parametrize("path", path_params(npms.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        assert pkgs.get(path)


class TestJSMetadata:
    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_name(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["name"] == metadata["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["lics"] == metadata["lics"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["versions"] == metadata["versions"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["latest"] == metadata["latest"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["origins"] == metadata["origins"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["sourcepkg"] == metadata["sourcepkg"]
