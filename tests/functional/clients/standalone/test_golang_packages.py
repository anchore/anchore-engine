import json


class TestGolangPackages:
    def test_go_packages(self, hints_image, analyzed_data):
        hints = {
            "packages": [
                {
                    "name": "kind",
                    "version": "v0.10.0",
                    "type": "go",
                    "license": "Apache2.0",
                },
            ]
        }
        result = hints_image(hints, "lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.go"
        ]["base"]
        package = json.loads(pkgs.get("/virtual/gopkg/kind-v0.10.0"))
        assert package["name"] == "kind"
        assert package["license"] == "Apache2.0"
        assert package["version"] == "v0.10.0"
