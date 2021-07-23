class TestOwnershipOverlap:
    def test_package_ownership_deduplication(self, analyzed_data):
        result = analyzed_data("ownership-overlap")
        package_list = result["image"]["imagedata"]["analysis_report"]["package_list"]
        os_pkgs = package_list["pkgs.all"]["base"]
        python_pkgs = package_list.get("pkgs.python", {"base": {}})["base"]

        assert os_pkgs.get("python-pil") == "6.2.1-3"
        for path in python_pkgs:
            assert "dist-packages/PIL" not in path
