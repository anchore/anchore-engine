import pytest

from .fixtures import binary


class TestBinary:
    def test_total_entries(self, analyzed_data):
        result = analyzed_data("bin")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.binary"
        ]["base"]
        assert len(pkgs) == len(binary.all_info)

    @pytest.mark.parametrize("path,metadata", binary.all_info.items())
    def test_each_metadata(self, analyzed_data, path, metadata):
        result = analyzed_data("bin")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.binary"
        ]["base"]
        assert pkgs.get(path) == metadata
