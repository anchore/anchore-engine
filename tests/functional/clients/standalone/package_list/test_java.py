# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import java
from . import path_params, metadata_params, assert_nested_dict_equal
import pytest
import json


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#

class TestGemPaths:

    @pytest.mark.parametrize('path', path_params(java.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("java")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.java']['base']
        assert pkgs.get(path)


class TestGemMetadata:

    @pytest.mark.parametrize('path,metadata,field', metadata_params(java.pkgs, 
        fields=("specification-version", "implementation-version", "maven-version", "origin", "location", "type", "name", "metadata"))
    )
    def test_has_field(self, analyzed_data, path, metadata, field):
        result = analyzed_data("java")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.java']['base']
        loaded = json.loads(pkgs.get(path, {}))
        assert loaded[field] == metadata[field]
