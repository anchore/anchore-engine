# from ['image']['imagedata']['analysis_report']['package_list']
from .fixtures import binary
from . import path_params, metadata_params
import pytest


#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#


class TestBinary:
    @pytest.mark.parametrize("path,metadata", binary.all_info.items())
    def test_all_metadata(self, analyzed_data, path, metadata):
        result = analyzed_data("bin")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"]["pkgs.binary"]["base"]
        assert pkgs.get(path) == metadata
