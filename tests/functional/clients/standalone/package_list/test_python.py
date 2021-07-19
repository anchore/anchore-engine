# from ['image']['imagedata']['analysis_report']['package_list']
import pytest

from . import path_params, metadata_params
from .fixtures import pypkgs


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
        loaded = pkgs.get(path, {})
        assert loaded["files"] == metadata["files"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["name"] == metadata["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_type(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["type"] == metadata["type"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_location(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["location"] == metadata["location"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_version(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["version"] == metadata["version"]

    @pytest.mark.parametrize("path,metadata", metadata_params(pypkgs.pkgs))
    def test_license(self, analyzed_data, path, metadata):
        result = analyzed_data("py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["license"] == metadata["license"]
