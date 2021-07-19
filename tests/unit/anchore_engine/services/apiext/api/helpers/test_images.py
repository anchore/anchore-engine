import pytest

from anchore_engine.services.apiext.api.helpers.image_content_response import (
    _build_default_response,
    _build_docker_history_response,
    _build_dockerfile_response,
    _build_gem_response,
    _build_java_response,
    _build_manifest_response,
    _build_npm_response,
    _build_os_response,
    _build_python_response,
)


class TestBuildOsResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "arch": "amd64",
            "license": "GPLv2+",
            "origin": "APT Development Team <deity@lists.debian.org> (maintainer)",
            "release": "N/A",
            "size": "4064000",
            "sourcepkg": "apt-1.8.2",
            "type": "dpkg",
            "version": "1.8.2",
            "cpes": [
                "cpe:2.3:*:*:apt:1.8.2:*:*:*:*:*:*:*",
                "cpe:2.3:*:apt:apt:1.8.2:*:*:*:*:*:*:*",
            ],
        }

    @pytest.fixture
    def multi_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        response["license"] += " MIT"
        return response

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "license": "GPLv2+",
                "licenses": ["GPLv2+"],
                "origin": "APT Development Team <deity@lists.debian.org> (maintainer)",
                "package": "apt",
                "size": "4064000",
                "type": "dpkg",
                "version": "1.8.2",
                "cpes": [
                    "cpe:2.3:*:*:apt:1.8.2:*:*:*:*:*:*:*",
                    "cpe:2.3:*:apt:apt:1.8.2:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_os_response({"apt": content_data_entry})

        assert expected_response == actual_response

    def test_multi_license(self, multi_license_content_data):
        expected_response = ["GPLv2+", "MIT"]

        actual_response = _build_os_response({"apt": multi_license_content_data})
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response


class TestBuildNpmResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "latest": None,
            "lics": ["Artistic-2.0"],
            "name": "npm-cli-docs",
            "origins": ["Tanya Brassie <tanyabrassie@tanyascmachine2.home>"],
            "sourcepkg": "https://github.com/npm/cli",
            "versions": ["0.1.0"],
            "cpes": [
                "cpe:2.3:*:*:npm-cli-docs:0.1.0:*:*:*:*:*:*:*",
                "cpe:2.3:*:npm-cli-docs:npm-cli-docs:0.1.0:*:*:*:*:*:*:*",
            ],
        }

    @pytest.fixture
    def multi_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        response["lics"].append("MIT")
        return response

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "license": "Artistic-2.0",
                "licenses": ["Artistic-2.0"],
                "location": "/usr/local/lib/node_modules/npm/docs/package.json",
                "origin": "Tanya Brassie <tanyabrassie@tanyascmachine2.home>",
                "package": "npm-cli-docs",
                "type": "NPM",
                "version": "0.1.0",
                "cpes": [
                    "cpe:2.3:*:*:npm-cli-docs:0.1.0:*:*:*:*:*:*:*",
                    "cpe:2.3:*:npm-cli-docs:npm-cli-docs:0.1.0:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_npm_response(
            {"/usr/local/lib/node_modules/npm/docs/package.json": content_data_entry}
        )

        assert expected_response == actual_response

    def test_multi_license(self, multi_license_content_data):
        expected_response = ["Artistic-2.0", "MIT"]

        actual_response = _build_npm_response(
            {
                "/usr/local/lib/node_modules/npm/docs/package.json": multi_license_content_data
            }
        )
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response


class TestBuildPythonResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "files": [
                "/usr/local/lib/python3.8/site-packages/../../../bin/pip",
                "/usr/local/lib/python3.8/site-packages/../../../bin/pip3",
            ],
            "license": "MIT",
            "location": "/usr/local/lib/python3.8/site-packages",
            "metadata": "some (truncated) metadata!",
            "name": "pip",
            "origin": "The pip developers <pypa-dev@groups.google.com>",
            "type": "python",
            "version": "20.0.2",
            "cpes": [
                "cpe:2.3:*:*:pip:20.0.2:*:*:*:*:*:*:*",
                "cpe:2.3:*:pip:pip:20.0.2:*:*:*:*:*:*:*",
            ],
        }

    @pytest.fixture
    def multi_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        response["license"] += " GPLv2"
        return response

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "license": "MIT",
                "licenses": ["MIT"],
                "location": "/usr/local/lib/python3.8/site-packages",
                "origin": "The pip developers <pypa-dev@groups.google.com>",
                "package": "pip",
                "type": "PYTHON",
                "version": "20.0.2",
                "cpes": [
                    "cpe:2.3:*:*:pip:20.0.2:*:*:*:*:*:*:*",
                    "cpe:2.3:*:pip:pip:20.0.2:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_python_response(
            {"/usr/local/lib/python3.8/site-packages/pip": content_data_entry}
        )

        assert expected_response == actual_response

    def test_multi_license(self, multi_license_content_data):
        expected_response = ["MIT", "GPLv2"]

        actual_response = _build_python_response(
            {"/usr/local/lib/python3.8/site-packages/pip": multi_license_content_data}
        )
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response


class TestBuildGemResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "files": ["exe/rake"],
            "latest": "13.0.1",
            "lics": ["MIT"],
            "name": "rake",
            "origins": ["Hiroshi SHIBATA", "Eric Hodel", "Jim Weirich"],
            "sourcepkg": "https://github.com/ruby/rake",
            "versions": ["13.0.1"],
            "cpes": [
                "cpe:2.3:*:*:rake:13.0.1:*:*:*:*:*:*:*",
                "cpe:2.3:*:rake:rake:13.0.1:*:*:*:*:*:*:*",
            ],
        }

    @pytest.fixture
    def multi_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        response["lics"].append("GPLv2")
        return response

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "license": "MIT",
                "licenses": ["MIT"],
                "location": "/usr/local/lib/ruby/gems/2.7.0/specifications/rake-13.0.1.gemspec",
                "origin": "Hiroshi SHIBATA,Eric Hodel,Jim Weirich",
                "package": "rake",
                "type": "GEM",
                "version": "13.0.1",
                "cpes": [
                    "cpe:2.3:*:*:rake:13.0.1:*:*:*:*:*:*:*",
                    "cpe:2.3:*:rake:rake:13.0.1:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_gem_response(
            {
                "/usr/local/lib/ruby/gems/2.7.0/specifications/rake-13.0.1.gemspec": content_data_entry
            }
        )

        assert expected_response == actual_response

    def test_multi_license(self, multi_license_content_data):
        expected_response = ["MIT", "GPLv2"]

        actual_response = _build_gem_response(
            {
                "/usr/local/lib/ruby/gems/2.7.0/specifications/rake-13.0.1.gemspec": multi_license_content_data
            }
        )
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response


class TestBuildJavaResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "implementation-version": "N/A",
            "location": "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar",
            "maven-version": "N/A",
            "metadata": {"MANIFEST.MF": "(truncated manifest data)"},
            "name": "charsets",
            "origin": "N/A",
            "specification-version": "N/A",
            "type": "java-jar",
            "cpes": [
                "cpe:2.3:*:*:charsets:N/A:*:*:*:*:*:*:*",
                "cpe:2.3:*:charsets:charsets:N/A:*:*:*:*:*:*:*",
            ],
        }

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "implementation-version": "N/A",
                "location": "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar",
                "maven-version": "N/A",
                "origin": "N/A",
                "package": "charsets",
                "specification-version": "N/A",
                "type": "JAVA-JAR",
                "cpes": [
                    "cpe:2.3:*:*:charsets:N/A:*:*:*:*:*:*:*",
                    "cpe:2.3:*:charsets:charsets:N/A:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_java_response(
            {
                "/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/charsets.jar": content_data_entry
            }
        )

        assert expected_response == actual_response


class TestBuildDefaultResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "license": "MIT",
            "location": "someplace",
            "metadata": "some (truncated) metadata",
            "name": "something",
            "origin": "someone",
            "type": "atype",
            "version": "20.0.2",
            "cpes": [
                "cpe:2.3:*:*:something:20.0.2:*:*:*:*:*:*:*",
                "cpe:2.3:*:something:something:20.0.2:*:*:*:*:*:*:*",
            ],
        }

    @pytest.fixture
    def multi_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        response["license"] += " GPLv2"
        return response

    @pytest.fixture
    def missing_license_content_data(self, content_data_entry):
        response = content_data_entry.copy()
        del response["license"]
        return response

    def test_go_case(self, content_data_entry):
        expected_response = [
            {
                "license": "MIT",
                "licenses": ["MIT"],
                "location": "someplace",
                "origin": "someone",
                "package": "something",
                "type": "ATYPE",
                "version": "20.0.2",
                "cpes": [
                    "cpe:2.3:*:*:something:20.0.2:*:*:*:*:*:*:*",
                    "cpe:2.3:*:something:something:20.0.2:*:*:*:*:*:*:*",
                ],
            }
        ]

        actual_response = _build_default_response({"a-place": content_data_entry})

        assert expected_response == actual_response

    def test_multi_license(self, multi_license_content_data):
        expected_response = ["MIT", "GPLv2"]

        actual_response = _build_default_response(
            {"someplace": multi_license_content_data}
        )
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response

    def test_missing_license(self, missing_license_content_data):
        expected_response = ["Unknown"]

        actual_response = _build_default_response(
            {"someplace": missing_license_content_data}
        )
        actual_pkg_response = actual_response[0]["licenses"]

        assert expected_response == actual_pkg_response


class TestBuildDockerHistoryResponse:
    @pytest.fixture
    def content_data_entry(self):
        return {
            "history": [
                {
                    "created": "2020-04-14T19:19:53.444488372Z",
                    "created_by": "/bin/sh -c #(nop) ADD file:xyz in / ",
                },
                {
                    "created": "2020-04-14T19:19:53.590635493Z",
                    "created_by": "/bin/sh -c #(nop)  CMD ['sh']",
                },
            ]
        }

    @pytest.fixture
    def bad_data_entry(self):
        return object()

    def test_go_case(self, content_data_entry):
        expected_response = """eyJoaXN0b3J5IjogW3siY3JlYXRlZCI6ICIyMDIwLTA0LTE0VDE5OjE5OjUzLjQ0NDQ4ODM3Mloi
LCAiY3JlYXRlZF9ieSI6ICIvYmluL3NoIC1jICMobm9wKSBBREQgZmlsZTp4eXogaW4gLyAifSwg
eyJjcmVhdGVkIjogIjIwMjAtMDQtMTRUMTk6MTk6NTMuNTkwNjM1NDkzWiIsICJjcmVhdGVkX2J5
IjogIi9iaW4vc2ggLWMgIyhub3ApICBDTUQgWydzaCddIn1dfQ==
"""

        actual_response = _build_docker_history_response(content_data_entry)

        assert expected_response == actual_response

    def test_parse_error_results_in_empty_response(self, bad_data_entry):
        expected_response = ""
        actual_response = _build_docker_history_response(bad_data_entry)
        assert expected_response == actual_response


class TestBuildDockerfileResponse:
    @pytest.fixture
    def content_data_entry(self):
        return "FROM ubuntu:14.04\nRUN cowsay"

    @pytest.fixture
    def bad_data_entry(self):
        return object()

    def test_go_case(self, content_data_entry):
        expected_response = "RlJPTSB1YnVudHU6MTQuMDQKUlVOIGNvd3NheQ==\n"

        actual_response = _build_dockerfile_response(content_data_entry)

        assert expected_response == actual_response

    def test_parse_error_results_in_empty_response(self, bad_data_entry):
        expected_response = ""
        actual_response = _build_dockerfile_response(bad_data_entry)
        assert expected_response == actual_response


class TestBuildManifestResponse:
    @pytest.fixture
    def content_data_entry(self):
        return """[
            {
                "Config": "be5888e67be651f1fbb59006f0fd791b44ed3fceaa6323ab4e37d5928874345a.json",
                "RepoTags": [
                "busybox:latest"
                ],
                "Layers": [
                "2a47214c4c9baacdb87c8db31b69daf5215add111e37eb7b07f2c1913483f9cc/layer.tar"
                ]
            }
        ]"""

    @pytest.fixture
    def bad_data_entry(self):
        return object()

    def test_go_case(self, content_data_entry):
        expected_response = """WwogICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAiQ29uZmlnIjogImJlNTg4OGU2N2JlNjUx
ZjFmYmI1OTAwNmYwZmQ3OTFiNDRlZDNmY2VhYTYzMjNhYjRlMzdkNTkyODg3NDM0NWEuanNvbiIs
CiAgICAgICAgICAgICAgICAiUmVwb1RhZ3MiOiBbCiAgICAgICAgICAgICAgICAiYnVzeWJveDps
YXRlc3QiCiAgICAgICAgICAgICAgICBdLAogICAgICAgICAgICAgICAgIkxheWVycyI6IFsKICAg
ICAgICAgICAgICAgICIyYTQ3MjE0YzRjOWJhYWNkYjg3YzhkYjMxYjY5ZGFmNTIxNWFkZDExMWUz
N2ViN2IwN2YyYzE5MTM0ODNmOWNjL2xheWVyLnRhciIKICAgICAgICAgICAgICAgIF0KICAgICAg
ICAgICAgfQogICAgICAgIF0=
"""

        actual_response = _build_manifest_response(content_data_entry)

        assert expected_response == actual_response

    def test_parse_error_results_in_empty_response(self, bad_data_entry):
        expected_response = ""
        actual_response = _build_manifest_response(bad_data_entry)
        assert expected_response == actual_response
