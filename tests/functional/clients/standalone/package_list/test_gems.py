# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import gems
from . import path_params, metadata_params
import pytest
import json


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#

gem_paths = [
    pytest.param(path, id=path.split('/')[-1]) for path, _ in gems.pkgs.items()
]

gem_metadata = [
    pytest.param(path, metadata, id=path.split('/')[-1]) for path, metadata in gems.pkgs.items()
]

def assert_nested_dict_equal(a, b):
    assert json.dumps(a, sort_keys=True, indent=2) == json.dumps(b, sort_keys=True, indent=2)

class TestGemPaths:

    @pytest.mark.parametrize('path', path_params(gems.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        assert pkgs.get(path)


class TestGemMetadata:

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_has_files(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['files'], metadata['files'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['name'], metadata['name'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['lics'], metadata['lics'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['versions'], metadata['versions'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['latest'], metadata['latest'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['origins'], metadata['origins'])

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = pkgs.get(path, {})
        assert_nested_dict_equal(loaded['sourcepkg'], metadata['sourcepkg'])
