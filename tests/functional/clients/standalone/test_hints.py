import json


def is_overwrite_msg_in_log(caplog, pkg, pkg_type):
    return f"{pkg} package already present under {pkg_type}" in caplog.text


class TestHintsNPM:
    def test_npm_hints(self, hints_image, caplog):
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
                {
                    "name": "lodash",
                    "location": "/node_modules/lodash/package.json",
                    "version": "1.9.4",
                    "license": "Not a real license",
                    "type": "npm",
                },
            ]
        }
        result = hints_image(hints, "npm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.npms"
        ]["base"]

        # Package not already present in report so verify it matches hint
        path = "/usr/lib/node_modules/npm/node_modules/string_decoder/node_modules/safe-buffer/package.json"
        package = pkgs.get(path)
        assert package["name"] == "safe-buffer"
        assert package["lics"] == ["FREE-FOR-ALL"]
        assert package["versions"] == ["100"]
        assert package.get("sourcepkg") == "safe-buffer"

        # Package not already present in report so verify it matches hint
        package = pkgs.get("/virtual/npmpkg/toure-awesome-1.0rc")
        assert package["name"] == "toure-awesome"
        assert package["lics"] == ["Propietary"]
        assert package["versions"] == ["1.0rc"]

        # Package already in report so verify hint did not overwrite it
        package = pkgs.get("/node_modules/lodash/package.json")
        assert package["name"] == "lodash"
        assert package["lics"] != ["Not a real license"]
        assert package["versions"] != ["1.9.4"]
        assert (
            is_overwrite_msg_in_log(
                caplog, "/node_modules/lodash/package.json", "pkgs.npm"
            )
            is True
        )


class TestHintsRPM:
    def test_rpm_hints(self, hints_image, caplog):
        hints = {
            "packages": [
                {
                    "name": "zlib",
                    "license": "test some other license",
                    "version": "987654:1.2.11-16.el8_2",
                    "type": "rpm",
                    "origin": "CentOS",
                },
                {
                    "name": "fedora-gpg-keys",
                    "version": "35-0.4",
                    "arch": "noarch",
                    "type": "rpm",
                    "license": "test-license",
                },
            ]
        }
        result = hints_image(hints, "rpm")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]

        # Package already in report so verify hint did not overwrite it
        package = pkgs.get("zlib")
        assert package["type"] == "rpm"
        assert package["license"] != "test some other license"
        assert "987654:1.2.11" not in package["version"]
        assert is_overwrite_msg_in_log(caplog, "zlib", "pkgs.allinfo") is True

        # Package not already present in report so verify it matches hint
        package = pkgs.get("fedora-gpg-keys")
        assert package["type"] == "rpm"
        assert package["license"] == "test-license"
        assert package["version"] == "35"


class TestHintsDPKG:
    def test_dpkg_hints(self, hints_image, caplog):
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

        # Package already in report so verify hint did not overwrite it
        package = pkgs.get("adduser")
        assert package["type"] == "dpkg"
        assert package["version"] != "43"
        assert package["license"] != "GPL"
        assert is_overwrite_msg_in_log(caplog, "adduser", "pkgs.allinfo") is True

        # Package not already present in report so verify it matches hint
        package = pkgs.get("master-alex")
        assert package["type"] == "dpkg"
        assert package["version"] == "0.0.1rc"
        assert package["license"] == "LGPLv8"


class TestHintsJava:
    def test_java_hints(self, hints_image, caplog):
        hints = {
            "packages": [
                {
                    "name": "TwilioNotifier-test-override",
                    "origin": "com.twilio.test-override",
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

        # Package already in report so verify hint did not overwrite it
        packages = pkgs.get("/TwilioNotifier.hpi")
        assert packages["type"] == "java-hpi"
        assert packages["location"] == "/TwilioNotifier.hpi"
        assert packages["origin"] != "com.twilio.test-override"
        assert packages["name"] != "TwilioNotifier-test-override"
        assert (
            is_overwrite_msg_in_log(caplog, "/TwilioNotifier.hpi", "pkgs.java") is True
        )

        # Package already in report so verify hint did not overwrite it
        packages = pkgs.get("/virtual/javapkg/developer-dan-193.28.jar")
        assert packages["type"] == "java-jar"
        assert packages["origin"] == "com.twilio.jenkins"
        assert packages["implementation-version"] == "193.28"


class TestHintsAPKG:
    def test_apkg_hints(self, hints_image, caplog):
        hints = {
            "packages": [
                {
                    "version": "2.2",
                    "sourcepkg": "alpine-keys",
                    "release": "r3",
                    "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                    "arch": "x86_64",
                    "license": "Apache",
                    "size": "1000",
                    "type": "APKG",
                    "name": "alpine-keys",
                },
                {
                    "version": "5.2",
                    "sourcepkg": "test-pkg",
                    "release": "r1",
                    "origin": "something",
                    "arch": "x86_64",
                    "license": "Apache",
                    "size": "200",
                    "type": "APKG",
                    "name": "test-pkg",
                },
            ]
        }

        result = hints_image(hints, "py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]

        # Package already in report so verify hint did not overwrite it
        packages = pkgs.get("alpine-keys")
        assert packages["type"] == "APKG"
        assert packages["size"] != "1000"
        assert packages["license"] != "Apache"
        assert packages["release"] != "r3"
        assert is_overwrite_msg_in_log(caplog, "alpine-keys", "pkgs.allinfo") is True

        # Package not already present in report so verify it matches hint
        packages = pkgs.get("test-pkg")
        assert packages["type"] == "APKG"
        assert packages["size"] == "200"
        assert packages["license"] == "Apache"
        assert packages["release"] == "r1"


class TestHintsPython:
    def test_python_hints(self, hints_image, caplog):
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
                {
                    "name": "hintstest",
                    "version": "3.2.1",
                    "type": "python",
                    "location": "/usr/lib/python3.8/my-site-packages",
                },
            ]
        }

        result = hints_image(hints, "py38")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]

        # Package not already present in report so verify it matches hint
        packages = pkgs.get("/usr/lib/python3.8/my-site-packages")
        assert packages["type"] == "python"
        assert packages["version"] == "1.9.1"
        assert packages["location"] == "/usr/lib/python3.8/my-site-packages"

        # Package not already present in report so verify it matches hint
        packages = pkgs.get("/virtual/pypkg/site-packages")
        assert packages["type"] == "python"
        assert packages["name"] == "hints-spectacular"
        assert packages["version"] == "1.0.0alpha"

        # Package already in report so verify hint did not overwrite it
        packages = pkgs.get("/usr/lib/python3.8/my-site-packages")
        assert packages["type"] == "python"
        assert packages["name"] != "hintstest"
        assert packages["version"] != "3.2.1"
        assert (
            is_overwrite_msg_in_log(
                caplog, "/usr/lib/python3.8/my-site-packages", "pkgs.python"
            )
            is True
        )


class TestHintsGem:
    def test_gem_hints(self, hints_image, caplog):
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
                {
                    "name": "test-override",
                    "licenses": ["license-override"],
                    "version": "3.2.0",
                    "origins": ["Zane"],
                    "source": "https://example.com/test-override",
                    "type": "gem",
                    "location": "/usr/lib/ruby/gems/2.7.0/specifications/bundler-2.1.4.gemspec",
                },
            ]
        }

        result = hints_image(hints, "lean")
        pkgs = result["image"]["imagedata"]["analysis_report"]["package_list"][
            "pkgs.gems"
        ]["base"]

        path = "/usr/lib/ruby/gems/2.7.0/specifications/default/uri-0.10.0.gemspec"
        packages = pkgs.get(path)
        # Package not already present in report so verify it matches hint
        assert packages["lics"] == ["GPL"]
        assert packages["versions"] == ["0.11.0"]
        assert packages["sourcepkg"] == "https://example.com"
        assert packages["type"] == "gem"

        # Package not already present in report so verify it matches hint
        packages = pkgs.get("/virtual/gempkg/diamonds-2.0")
        assert packages["type"] == "gem"
        assert packages["versions"] == ["2.0"]

        # Package already in report so verify hint did not overwrite it
        packages = pkgs.get(
            "/usr/lib/ruby/gems/2.7.0/specifications/bundler-2.1.4.gemspec"
        )
        assert packages["lics"] != ["license-override"]
        assert packages["versions"] != ["3.2.0"]
        assert packages["sourcepkg"] != "https://example.com/test-override"
        assert (
            is_overwrite_msg_in_log(
                caplog,
                "/usr/lib/ruby/gems/2.7.0/specifications/bundler-2.1.4.gemspec",
                "pkgs.gems",
            )
            is True
        )


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
        # Package not already present in report so verify it matches hint
        assert package["name"] == "kind"
        assert package["license"] == "Apache2.0"
        assert package["version"] == "v0.10.0"
