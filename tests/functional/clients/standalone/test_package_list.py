# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import gems
import pytest
import json


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#

gem_paths = [
    pytest.param(path, id=path.split('/')[-1]) for path, _ in gems.pkgs
]

gem_metadata = [
    pytest.param(path, metadata, id=path.split('/')[-1]) for path, metadata in gems.pkgs
]


class TestGemPaths:

    @pytest.mark.parametrize('path', gem_paths)
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        assert pkgs.get(path)


class TestGemMetadata:

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_has_files(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path, "{}"))
        expected = json.loads(metadata)
        assert loaded['files'] == expected['files']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['name'] == expected['name']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['lics'] == expected['lics']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['versions'] == expected['versions']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['latest'] == expected['latest']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['origins'] == expected['origins']

    @pytest.mark.parametrize('path,metadata', gem_metadata)
    def test_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['sourcepkg'] == expected['sourcepkg']
