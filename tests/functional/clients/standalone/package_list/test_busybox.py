class TestPksAll:
    def test_all_packages_exist(self, analyzed_data):
        result = analyzed_data("busybox")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.all"
        ]["base"]
        assert pkgs == {"BusyBox": "1.32.0"}
