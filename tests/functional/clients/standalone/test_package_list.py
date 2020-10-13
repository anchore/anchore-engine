# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import gems, pypkgs, npms
import pytest
import json


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#
def path_params(pkgs):
    """
    A helper to produce a list of tuples with better output when Pytest runs.
    By default, Pytest will use the full value of the string, which in the case
    of these fixtures is too long, causing unreadable output.
    """
    return [
        pytest.param(path, id=path.split('/')[-1]) for path, _ in pkgs
    ]


def metadata_params(pkgs):
    """
    Similarly to `path_params`, the idea is to produce readable output when
    running pytest by using `pytest.param` and reduced string representation
    from the values passed in
    """
    return [
        pytest.param(path, metadata, id=path.split('/')[-1]) for path, metadata in pkgs
    ]


class TestJSPaths:

    @pytest.mark.parametrize('path', path_params(npms.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("npm")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        assert pkgs.get(path)


class TestJSMetadata:

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_name(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['name'] == expected['name']

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_lics(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['lics'] == expected['lics']

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_versions(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['versions'] == expected['versions']

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_latest(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['latest'] == expected['latest']

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_origins(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['origins'] == expected['origins']

    @pytest.mark.parametrize('path,metadata', metadata_params(npms.pkgs))
    def test_has_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data('npm')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['sourcepkg'] == expected['sourcepkg']


class TestPythonPaths:

    @pytest.mark.parametrize('path', path_params(pypkgs.pkgs))
    def test_all_packages_exist(self, analyzed_data, path):
        result = analyzed_data("py38")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        assert pkgs.get(path)


class TestPythonMetadata:

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_has_files(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['files'] == expected['files']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['name'] == expected['name']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_type(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['type'] == expected['type']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_location(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['location'] == expected['location']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_version(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['version'] == expected['version']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_license(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['license'] == expected['license']

    @pytest.mark.parametrize('path,metadata', metadata_params(pypkgs.pkgs))
    def test_metadata(self, analyzed_data, path, metadata):
        result = analyzed_data('py38')
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['metadata'] == expected['metadata']


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
        loaded = json.loads(pkgs.get(path, "{}"))
        expected = json.loads(metadata)
        assert loaded['files'] == expected['files']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_name(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['name'] == expected['name']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_lics(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['lics'] == expected['lics']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_versions(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['versions'] == expected['versions']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_latest(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['latest'] == expected['latest']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_origins(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['origins'] == expected['origins']

    @pytest.mark.parametrize('path,metadata', metadata_params(gems.pkgs))
    def test_sourcepkg(self, analyzed_data, path, metadata):
        result = analyzed_data("lean")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
        loaded = json.loads(pkgs.get(path))
        expected = json.loads(metadata)
        assert loaded['sourcepkg'] == expected['sourcepkg']
