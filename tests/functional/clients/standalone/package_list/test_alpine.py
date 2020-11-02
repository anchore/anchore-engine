import sys
from .fixtures import alpine
from . import path_params
import json
import pytest


class TestAlpinePaths:

    @pytest.mark.parametrize('path', path_params(alpine.pkgfiles_all))
    def test_pkgfiles_all(self, analyzed_data, path):
        result = analyzed_data("py38")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgfiles.all']['base']
        assert pkgs.get(path) == 'APKFILE'

    @pytest.mark.parametrize('pkg,version', [pytest.param(pkg, version, id=pkg) for pkg, version in alpine.pkgs_all.items()])
    def test_pkgs_all(self, analyzed_data, pkg, version):
        result = analyzed_data("py38")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.all']['base']
        assert pkgs.get(pkg) == version

    @pytest.mark.parametrize('pkg,metadata', alpine.pkgs_allinfo.items())
    def test_pkgs_allinfo(self, analyzed_data, pkg, metadata):
        result = analyzed_data("py38")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs.allinfo']['base']
        loaded = json.loads(pkgs.get(pkg, '{}'))
        assert loaded == metadata

    @pytest.mark.parametrize('pkg,version', [pytest.param(pkg, version, id=pkg) for pkg, version in alpine.pkgs_all.items()])
    def test_pkgs_plus_source_all(self, analyzed_data, pkg, version):
        result = analyzed_data("py38")
        pkgs = result['image']['imagedata']['analysis_report']['package_list']['pkgs_plus_source.all']['base']
        assert pkgs.get(pkg) == version
