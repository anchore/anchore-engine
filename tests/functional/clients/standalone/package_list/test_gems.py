# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import gems
from . import path_params, metadata_params
import pytest
import json


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
        loaded = json.loads(pkgs.get(path, "{}"))
        expected = json.loads(metadata)
        assert loaded["files"] == expected["files"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["name"] == expected["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["lics"] == expected["lics"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["versions"] == expected["versions"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["latest"] == expected["latest"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["origins"] == expected["origins"]

    @pytest.mark.parametrize("path,metadata", metadata_params(gems.pkgs))
    def test_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["sourcepkg"] == expected["sourcepkg"]
