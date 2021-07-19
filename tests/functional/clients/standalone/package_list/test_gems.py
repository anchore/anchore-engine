# from ['image']['imagedata']['analysis_report']['package_list']
import pytest

from . import path_params, metadata_params
from .fixtures import gems


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#


class TestGemPaths:
    @pytest.mark.parametrize("path", path_params(gems.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        assert pkgs.get(path)


class TestGemMetadata:
    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_has_files(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["files"] == metadata["files"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["name"] == metadata["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["lics"] == metadata["lics"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["versions"] == metadata["versions"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["latest"] == metadata["latest"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["origins"] == metadata["origins"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["sourcepkg"] == metadata["sourcepkg"]
