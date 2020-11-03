# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import npms
from . import path_params, metadata_params
import pytest
import json


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
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["name"] == expected["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["lics"] == expected["lics"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["versions"] == expected["versions"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["latest"] == expected["latest"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["origins"] == expected["origins"]

    @pytest.mark.parametrize("path,metadata", metadata_params(npms.pkgs))
    def test_has_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["sourcepkg"] == expected["sourcepkg"]
