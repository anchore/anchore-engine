import json


class TestHintsNPM:
    def test_npm_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "safe-buffer",
                    "location": "/usr/lib/node_modules/npm/node_modules/string_decoder/node_modules/safe-buffer/package.json",
                    "license": "FREE-FOR-ALL",
                    "version": "100",
                    "type": "npm",
                },
                {
                    "name": "toure-awesome",
                    "license": "Propietary",
                    "version": "1.0rc",
                    "type": "npm",
                },
            ]
        }
        result = hints_image(hints, "npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]
        path = "/usr/lib/node_modules/npm/node_modules/string_decoder/node_modules/safe-buffer/package.json"
        package = pkgs.get(path)
        assert package["name"] == "safe-buffer"
        assert package["lics"] == ["FREE-FOR-ALL"]
        assert package["versions"] == ["100"]
        assert package.get("sourcepkg") == "safe-buffer"

        # Include non-existent package from a custom hint
        package = pkgs.get("/virtual/npmpkg/toure-awesome-1.0rc")
        assert package["name"] == "toure-awesome"
        assert package["lics"] == ["Propietary"]
        assert package["versions"] == ["1.0rc"]


class TestHintsRPM:
    def test_rpm_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "zlib",
                    "license": "zlib and Boost",
                    "version": "987654:1.2.11-16.el8_2",
                    "type": "rpm",
                    "origin": "CentOS",
                }
            ]
        }
        result = hints_image(hints, "rpm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        package = pkgs.get("zlib")
        assert package["type"] == "rpm"
        assert package["license"] == "zlib and Boost"
        assert package["version"] == "987654:1.2.11"
        assert package["origin"] == "CentOS"


class TestHintsDPKG:
    def test_dpkg_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "adduser",
                    "version": "43",
                    "license": "GPL",
                    "type": "dpkg",
                },
                {
                    "name": "master-alex",
                    "version": "0.0.1rc",
                    "license": "LGPLv8",
                    "type": "dpkg",
                },
            ]
        }
        result = hints_image(hints, "stretch-slim")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        package = pkgs.get("adduser")
        assert package["type"] == "dpkg"
        assert package["version"] == "43"
        assert package["license"] == "GPL"

        package = pkgs.get("master-alex")
        assert package["type"] == "dpkg"
        assert package["version"] == "0.0.1rc"
        assert package["license"] == "LGPLv8"


class TestHintsJava:
    def test_java_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "TwilioNotifier",
                    "origin": "com.twilio.jenkins",
                    "location": "/TwilioNotifier.hpi",
                    "type": "java",
                    "version": "N/A",
                },
                {
                    "name": "developer-dan",
                    "origin": "com.twilio.jenkins",
                    "type": "java",
                    "version": "193.28",
                },
            ]
        }
        result = hints_image(hints, "java")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.java"
        ]["base"]
        packages = pkgs.get("/TwilioNotifier.hpi")
        assert packages["type"] == "java-jar"
        assert packages["location"] == "/TwilioNotifier.hpi"
        assert packages["origin"] == "com.twilio.jenkins"

        packages = pkgs.get("/virtual/javapkg/developer-dan-193.28.jar")
        assert packages["type"] == "java-jar"
        assert packages["origin"] == "com.twilio.jenkins"
        assert packages["implementation-version"] == "193.28"


class TestHintsAPKG:
    def test_apkg_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "version": "2.2",
                    "sourcepkg": "alpine-keys",
                    "release": "r0",
                    "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                    "arch": "x86_64",
                    "license": "MIT",
                    "size": "1000",
                    "type": "APKG",
                    "name": "alpine-keys",
                }
            ]
        }

        result = hints_image(hints, "py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        packages = pkgs.get("alpine-keys")
        assert packages["type"] == "APKG"
        assert packages["size"] == "1000"
        assert packages["license"] == "MIT"
        assert packages["release"] == "r0"


class TestHintsPython:
    def test_python_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "py",
                    "version": "1.9.1",
                    "type": "python",
                    "location": "/usr/lib/python3.8/my-site-packages",
                },
                {
                    "name": "hints-spectacular",
                    "version": "1.0.0alpha",
                    "type": "python",
                },
            ]
        }

        result = hints_image(hints, "py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        packages = pkgs.get("/usr/lib/python3.8/my-site-packages")

        assert packages["type"] == "python"
        assert packages["version"] == "1.9.1"
        assert packages["location"] == "/usr/lib/python3.8/my-site-packages"

        packages = pkgs.get("/virtual/pypkg/site-packages")
        assert packages["type"] == "python"
        assert packages["name"] == "hints-spectacular"
        assert packages["version"] == "1.0.0alpha"


class TestHintsGem:
    def test_gem_hints(self, hints_image):
        hints = {
            "packages": [
                {
                    "name": "uri",
                    "licenses": ["GPL"],
                    "version": "0.11.0",
                    "origins": ["Akira Yamada"],
                    "source": "https://example.com",
                    "type": "gem",
                    "location": "/usr/lib/ruby/gems/2.7.0/specifications/default/uri-0.10.0.gemspec",
                },
                {
                    "name": "diamonds",
                    "version": "2.0",
                    "type": "gem",
                },
            ]
        }

        result = hints_image(hints, "lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]
        path = "/usr/lib/ruby/gems/2.7.0/specifications/default/uri-0.10.0.gemspec"
        packages = pkgs.get(path)
        assert packages["lics"] == ["GPL"]
        assert packages["versions"] == ["0.11.0"]
        assert packages["sourcepkg"] == "https://example.com"
        assert packages["type"] == "gem"

        packages = pkgs.get("/virtual/gempkg/diamonds-2.0")
        assert packages["type"] == "gem"
        assert packages["versions"] == ["2.0"]


class TestHintsGo:
    def test_go_hints(self, hints_image, analyzed_data):
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
