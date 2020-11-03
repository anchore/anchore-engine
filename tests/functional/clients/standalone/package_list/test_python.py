# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import pypkgs
from . import path_params, metadata_params
import pytest
import json


class TestPythonPaths:
    @pytest.mark.parametrize("path", path_params(pypkgs.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        assert pkgs.get(path)


class TestPythonMetadata:
    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_has_files(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["files"] == expected["files"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["name"] == expected["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_type(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["type"] == expected["type"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_location(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["location"] == expected["location"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_version(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["version"] == expected["version"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_license(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["license"] == expected["license"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_metadata(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded["metadata"] == expected["metadata"]
