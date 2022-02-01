import pytest

from . import metadata_params, path_params
from .fixtures import golang


class TestGoPaths:
    @pytest.mark.parametrize("path", path_params(golang.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        print(path)
        assert pkgs.get(path)


class TestGoMetadata:
    @pytest.mark.parametrize("path,metadata", metadata_params(golang.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["name"] == metadata["name"]

    @pytest.mark.parametrize("path,metadata", metadata_params(golang.pkgs))
    def test_type(self, analyzed_data, path, metadata):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["type"] == metadata["type"]

    @pytest.mark.parametrize("path,metadata", metadata_params(golang.pkgs))
    def test_location(self, analyzed_data, path, metadata):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["location"] == metadata["location"]

    @pytest.mark.parametrize("path,metadata", metadata_params(golang.pkgs))
    def test_version(self, analyzed_data, path, metadata):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["version"] == metadata["version"]

    @pytest.mark.parametrize("path,metadata", metadata_params(golang.pkgs))
    def test_license(self, analyzed_data, path, metadata):
        result = analyzed_data("go")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        loaded = pkgs.get(path, {})
        assert loaded["license"] == metadata["license"]
