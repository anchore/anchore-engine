# from ['image']['imagedata']['analysis_report']['package_list']
import pytest

from . import metadata_params, path_params
from .fixtures import java

#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#


class TestJavaPath:
    @pytest.mark.parametrize("path", path_params(java.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("java")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.java"
        ]["base"]
        assert pkgs.get(path)


class TestJavaMetadata:
    @pytest.mark.parametrize(
        "path,metadata,field",
        metadata_params(
            java.pkgs,
            fields=(
                "specification-version",
                "implementation-version",
                "maven-version",
                "origin",
                "location",
                "type",
                "name",
            ),
        ),
    )
    def test_has_field(self, analyzed_data, path, metadata, field):
        result = analyzed_data("java")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.java"
        ]["base"]
        loaded = pkgs.get(path, {})
        actual_value = loaded[field]
        expected_value = metadata[field]
        assert actual_value == expected_value
