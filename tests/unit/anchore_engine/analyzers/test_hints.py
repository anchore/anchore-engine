import pytest

from anchore_engine.analyzers.hints import (
    BaseHint,
    HintsTypeError,
    RPMHint,
    PythonHint,
    GoHint,
    BinaryHint,
    DebianHint,
    AlpineHint,
    GemHint,
    NPMHint,
    JavaHint,
)


class TestBaseHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "version": "1.0.0",
                    },
                    "type": "rpm",
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="missing_name",
            ),
            pytest.param(
                {
                    "pkg": {"name": "kind"},
                    "type": "rpm",
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="missing_version",
            ),
            pytest.param(
                {
                    "pkg": {"name": "kind", "version": "1.0.0"},
                    "type": "",
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="missing_type",
            ),
            pytest.param(
                {
                    "pkg": {"name": "kind", "version": "1.0.0"},
                    "type": "rpm",
                    "expected_error": "",
                },
                id="valid",
            ),
        ],
    )
    def test_check_required_fields(self, param):
        hint = BaseHint(param["pkg"], param["type"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.check_required_fields()
        else:
            hint.check_required_fields()

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "version": "1.0.0",
                    },
                    "key": "version",
                    "expected": ["1.0.0"],
                },
                id="singular-only",
            ),
            pytest.param(
                {
                    "pkg": {
                        "versions": [
                            "1.0.0",
                        ],
                    },
                    "key": "version",
                    "expected": ["1.0.0"],
                },
                id="plural-only",
            ),
            pytest.param(
                {
                    "pkg": {
                        "version": "2.0.0",
                        "versions": [
                            "1.0.0",
                        ],
                    },
                    "key": "version",
                    "expected": ["1.0.0"],
                },
                id="both",
            ),
            pytest.param(
                {"pkg": {}, "key": "version", "expected": []},
                id="neither",
            ),
            pytest.param({"pkg": {}, "key": None, "expected": []}, id="none-key"),
            pytest.param({"pkg": {}, "key": "", "expected": []}, id="empty-key"),
        ],
    )
    def test_get_list_value(self, param):
        actual = BaseHint.get_list_value(param["pkg"], param["key"])
        assert actual == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.0.0",
                        "origin": "Anchore, Inc.",
                    },
                    "type": "apkg",
                    "expected": {
                        "type": "apkg",
                        "name": "zlib",
                        "version": "1.0.0",
                        "origin": "Anchore, Inc.",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "type": "",
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.0.0",
                    },
                    "type": "apkg",
                    "expected": {
                        "type": "apkg",
                        "name": "zlib",
                        "version": "1.0.0",
                        "origin": "",
                    },
                    "expected_error": "",
                },
                id="required-fields",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = BaseHint(param["pkg"], param["type"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestRPMHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-16.el8_2",
                        "arch": "x86_64",
                    },
                    "expected": ("zlib", "1.2.11", "16.el8_2", "", "x86_64"),
                    "expected_error": "",
                },
                id="valid",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "fedora-release-identity-container",
                        "version": "35",
                        "release": "0.7",
                        "arch": "noarch",
                        "type": "rpm",
                    },
                    "expected": (
                        "fedora-release-identity-container",
                        "35",
                        "0.7",
                        "",
                        "noarch",
                    ),
                    "expected_error": "",
                },
                id="valid-release-no-source",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "tzdata",
                        "version": "2021a",
                        "release": "1.fc34",
                        "arch": "noarch",
                        "type": "rpm",
                    },
                    "expected": ("tzdata", "2021a", "1.fc34", "", "noarch"),
                    "expected_error": "",
                },
                id="valid-release-no-source",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "zlib-16.el8_2",
                        "arch": "x86_64",
                    },
                    "expected": None,
                    "expected_error": "hints package version for hints package \\(zlib\\) is not valid for RPM package type",
                },
                id="name-matches-parsed-version",
            ),
        ],
    )
    def test_resolve_rpm_fields(self, param):
        hint = RPMHint(param["pkg"])
        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.resolve_rpm_fields()
        else:
            assert hint.resolve_rpm_fields() == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-16.el8_2",
                        "arch": "x86_64",
                    },
                    "expected": {
                        "version": "1.2.11",
                        "release": "16.el8_2",
                        "arch": "x86_64",
                        "source": "zlib-1.2.11-16.el8_2.src.rpm",
                    },
                },
                id="basic-flow-no-epoch-no-source",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-16.el8_2",
                        "arch": "x86_64",
                        "source": "zlibsrc",
                    },
                    "expected": {
                        "version": "1.2.11",
                        "release": "16.el8_2",
                        "arch": "x86_64",
                        "source": "zlibsrc-1.2.11.src.rpm",
                    },
                },
                id="basic-flow-no-epoch",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "987654:1.2.11-16.el8_2",
                        "arch": "x86_64",
                        "source": "zlibsrc",
                    },
                    "expected": {
                        "version": "987654:1.2.11",
                        "release": "16.el8_2",
                        "arch": "x86_64",
                        "source": "zlibsrc-987654:1.2.11.src.rpm",
                    },
                },
                id="basic-flow",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "987654:1.2.11-16.el8_2",
                        "arch": "amd64",
                        "source": "zlibsrc",
                    },
                    "expected": {
                        "version": "987654:1.2.11",
                        "release": "16.el8_2",
                        "arch": "x86_64",
                        "source": "zlibsrc-987654:1.2.11.src.rpm",
                    },
                },
                id="basic-flow-amd64",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = RPMHint(param["pkg"])
        hint.normalize()
        assert hint.version == param["expected"]["version"]
        assert hint.release == param["expected"]["release"]
        assert hint.arch == param["expected"]["arch"]
        assert hint.source == param["expected"]["source"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "987654:1.2.11-16.el8_2",
                        "origin": "CentOS",
                        "arch": "amd64",
                        "release": "el8_2",
                        "source": "zlibsrc",
                        "size": "195719",
                        "license": "zlib and Boost",
                    },
                    "expected": {
                        "type": "rpm",
                        "name": "zlib",
                        "version": "987654:1.2.11-16.el8_2",
                        "origin": "CentOS",
                        "license": "zlib and Boost",
                        "arch": "x86_64",
                        "release": "el8_2",
                        "sourcepkg": "zlibsrc",
                        "size": "195719",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "987654:1.2.11-16.el8_2",
                    },
                    "expected": {
                        "type": "rpm",
                        "name": "zlib",
                        "version": "987654:1.2.11",
                        "origin": "",
                        "license": "",
                        "arch": "x86_64",
                        "release": "16.el8_2",
                        "sourcepkg": "zlib-987654:1.2.11-16.el8_2.src.rpm",
                        "size": "0",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = RPMHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestPythonHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "files": [
                            "file1",
                            "file2",
                        ],
                        "name": "pytest",
                    },
                    "expected_error": "",
                },
                id="valid-files",
            ),
            pytest.param(
                {
                    "pkg": {
                        "files": "file1",
                        "name": "pytest",
                    },
                    "expected_error": "bad hints record \\(pytest\\), files, if specified must be list type",
                },
                id="invalid-files",
            ),
        ],
    )
    def test_validate_files(self, param):
        hint = PythonHint(param["pkg"])
        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.validate_files()
        else:
            hint.validate_files()

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "files": [
                            "file1",
                            "file2",
                        ],
                        "name": "pytest",
                    },
                    "expected": "/virtual/pypkg/site-packages",
                    "expected_error": "",
                },
                id="valid-files",
            ),
            pytest.param(
                {
                    "pkg": {
                        "files": "file1",
                        "name": "pytest",
                    },
                    "expected": "",
                    "expected_error": "bad hints record \\(pytest\\), files, if specified must be list type",
                },
                id="invalid-files",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = PythonHint(param["pkg"])
        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.normalize()
        else:
            hint.normalize()
            assert hint.location == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "toml",
                        "version": "0.10.2",
                        "origin": "William Pearson <uiri@xqz.ca",
                        "license": "MIT",
                        "files": ["file1"],
                        "metadata": {"key": "value"},
                        "location": "/usr/lib/python3.8/site-packages/toml",
                    },
                    "expected": {
                        "type": "python",
                        "name": "toml",
                        "version": "0.10.2",
                        "origin": "William Pearson <uiri@xqz.ca",
                        "license": "MIT",
                        "files": ["file1"],
                        "metadata": '{"key": "value"}',
                        "location": "/usr/lib/python3.8/site-packages/toml",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "toml",
                        "version": "0.10.2",
                    },
                    "expected": {
                        "type": "python",
                        "name": "toml",
                        "version": "0.10.2",
                        "origin": "",
                        "license": "",
                        "files": [],
                        "metadata": "{}",
                        "location": "/virtual/pypkg/site-packages",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = PythonHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestGoHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "Anchore Engineering <engineering@anchore.com>",
                        "license": "Apache2.0",
                        "arch": "x86_64",
                        "source": "rem",
                        "size": "101010",
                        "metadata": {"key": "value"},
                        "location": "/rem",
                    },
                    "expected": {
                        "type": "go",
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "Anchore Engineering <engineering@anchore.com>",
                        "license": "Apache2.0",
                        "arch": "x86_64",
                        "sourcepkg": "rem",
                        "size": "101010",
                        "metadata": '{"key": "value"}',
                        "location": "/rem",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rem",
                        "version": "v0.1.8",
                    },
                    "expected": {
                        "type": "go",
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "",
                        "license": "",
                        "arch": "x86_64",
                        "sourcepkg": "",
                        "size": "0",
                        "metadata": "{}",
                        "location": "",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = GoHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestBinaryHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "files": [
                            "file1",
                            "file2",
                        ],
                        "name": "busybox",
                    },
                    "expected_error": "",
                },
                id="valid-files",
            ),
            pytest.param(
                {
                    "pkg": {
                        "files": "file1",
                        "name": "busybox",
                    },
                    "expected_error": "bad hints record \\(busybox\\), files, if specified must be list type",
                },
                id="invalid-files",
            ),
        ],
    )
    def test_validate_files(self, param):
        hint = BinaryHint(param["pkg"])
        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.validate_files()
        else:
            hint.validate_files()

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "files": [
                            "file1",
                            "file2",
                        ],
                        "name": "busybox",
                    },
                    "expected_error": "",
                },
                id="valid-files",
            ),
            pytest.param(
                {
                    "pkg": {
                        "files": "file1",
                        "name": "busybox",
                    },
                    "expected_error": "bad hints record \\(busybox\\), files, if specified must be list type",
                },
                id="invalid-files",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = BinaryHint(param["pkg"])
        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.normalize()
        else:
            hint.normalize()

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "Anchore Engineering <engineering@anchore.com>",
                        "license": "Apache2.0",
                        "files": [
                            "file1",
                        ],
                        "metadata": {"key": "value"},
                        "location": "/rem",
                    },
                    "expected": {
                        "type": "binary",
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "Anchore Engineering <engineering@anchore.com>",
                        "license": "Apache2.0",
                        "files": [
                            "file1",
                        ],
                        "metadata": '{"key": "value"}',
                        "location": "/rem",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rem",
                        "version": "v0.1.8",
                    },
                    "expected": {
                        "type": "binary",
                        "name": "rem",
                        "version": "v0.1.8",
                        "origin": "",
                        "license": "",
                        "files": [],
                        "metadata": "{}",
                        "location": "",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = BinaryHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestDebianHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                        "release": "abc",
                    },
                    "expected": {
                        "source": "zlib1g-dev-1:1.2.8.dfsg-5",
                        "release": "N/A",
                    },
                },
                id="no-source",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                        "source": "debian",
                        "release": "abc",
                    },
                    "expected": {"source": "debian", "release": "N/A"},
                },
                id="with-source",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = DebianHint(param["pkg"])
        hint.normalize()
        assert hint.source == param["expected"]["source"]
        assert hint.release == param["expected"]["release"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                        "origin": "Mark Brown <broonie@debian.org> (maintainer)",
                        "license": "Unknown",
                        "arch": "unknown",
                        "release": "releasetest",
                        "source": "sourctest",
                        "size": "1234",
                    },
                    "expected": {
                        "type": "dpkg",
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                        "origin": "Mark Brown <broonie@debian.org> (maintainer)",
                        "license": "Unknown",
                        "arch": "unknown",
                        "release": "N/A",
                        "sourcepkg": "sourctest",
                        "size": "1234",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                    },
                    "expected": {
                        "type": "dpkg",
                        "name": "zlib1g-dev",
                        "version": "1:1.2.8.dfsg-5",
                        "origin": "",
                        "license": "",
                        "arch": "x86_64",
                        "release": "N/A",
                        "sourcepkg": "zlib1g-dev-1:1.2.8.dfsg-5",
                        "size": "0",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = DebianHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestAlpineHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                        "source": "sourcetest",
                        "release": "releasetest",
                    },
                    "expected": {
                        "source": "sourcetest",
                        "release": "releasetest",
                        "version": "1.2.11-r3",
                    },
                    "expected_error": "",
                },
                id="source-and-release",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                        "source": "sourcetest",
                    },
                    "expected": {
                        "source": "sourcetest",
                        "release": "r3",
                        "version": "1.2.11",
                    },
                    "expected_error": "",
                },
                id="source-no-release",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                        "release": "r3",
                    },
                    "expected": {
                        "source": "zlib",
                        "release": "r3",
                        "version": "1.2.11-r3",
                    },
                    "expected_error": "",
                },
                id="release-no-source",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11",
                        "source": "sourcetest",
                    },
                    "expected": {},
                    "expected_error": "hints package version for hints package \\(zlib\\) is not valid for APKG package type",
                },
                id="no-release-malformed-version",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = AlpineHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.normalize()
        else:
            hint.normalize()
            assert hint.source == param["expected"]["source"]
            assert hint.release == param["expected"]["release"]
            assert hint.version == param["expected"]["version"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                        "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                        "license": "Zlib",
                        "arch": "amd64",
                        "release": "releasetest",
                        "source": "sourctest",
                        "size": "1234",
                        "files": [
                            "file1",
                        ],
                    },
                    "expected": {
                        "type": "APKG",
                        "name": "zlib",
                        "version": "1.2.11-r3",
                        "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                        "license": "Zlib",
                        "arch": "amd64",
                        "release": "releasetest",
                        "sourcepkg": "sourctest",
                        "size": "1234",
                        "files": [
                            "file1",
                        ],
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                    },
                    "expected": {
                        "type": "APKG",
                        "name": "zlib",
                        "version": "1.2.11",
                        "origin": "",
                        "license": "",
                        "arch": "x86_64",
                        "release": "r3",
                        "sourcepkg": "zlib",
                        "size": "0",
                        "files": [],
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = AlpineHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestGemHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {"location": "/usr/share/location"},
                    "expected_error": "",
                },
                id="valid-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "versions": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(rubylib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-version-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "licenses": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(rubylib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-license-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "version": "1.0.0",
                        "origins": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(rubylib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-origin-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "versions": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": "file1",
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(rubylib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-files-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                    },
                    "expected": {"location": "/virtual/gempkg/rubylib-1.0.0"},
                    "expected_error": "",
                },
                id="valid-without-location",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = GemHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.normalize()
        else:
            hint.normalize()
            assert hint.location == param["expected"]["location"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "rubylib",
                        "version": "1.0.0",
                        "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                        "license": "unknown",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/hey/there",
                    },
                    "expected": {
                        "type": "gem",
                        "name": "rubylib",
                        "versions": ["1.0.0"],
                        "latest": "1.0.0",
                        "origins": ["Natanael Copa <ncopa@alpinelinux.org>"],
                        "lics": ["unknown"],
                        "sourcepkg": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/hey/there",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                    },
                    "expected": {
                        "type": "gem",
                        "name": "zlib",
                        "versions": ["1.2.11-r3"],
                        "latest": "1.2.11-r3",
                        "origins": [],
                        "lics": [],
                        "sourcepkg": "zlib",
                        "files": [],
                        "location": "/virtual/gempkg/zlib-1.2.11-r3",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = GemHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestNPMHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {"location": "/usr/share/location"},
                    "expected_error": "",
                },
                id="valid-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "versions": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(nodelib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-version-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "licenses": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(nodelib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-license-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "version": "1.0.0",
                        "origins": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(nodelib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-origin-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "versions": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": "file1",
                        "location": "/usr/share/location",
                    },
                    "expected": {},
                    "expected_error": "bad hints record \\(nodelib\\), versions, licenses, origins, and files if specified must be list types",
                },
                id="invalid-files-with-location",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "version": "1.0.0",
                        "origin": "Anchore <anchore@anchore.com>",
                        "license": "Apache2.0",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                    },
                    "expected": {"location": "/virtual/npmpkg/nodelib-1.0.0"},
                    "expected_error": "",
                },
                id="valid-without-location",
            ),
        ],
    )
    def test_normalize(self, param):
        hint = NPMHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.normalize()
        else:
            hint.normalize()
            assert hint.location == param["expected"]["location"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "nodelib",
                        "version": "1.0.0",
                        "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                        "license": "unknown",
                        "source": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/hey/there",
                    },
                    "expected": {
                        "type": "npm",
                        "name": "nodelib",
                        "versions": ["1.0.0"],
                        "latest": "1.0.0",
                        "origins": ["Natanael Copa <ncopa@alpinelinux.org>"],
                        "lics": ["unknown"],
                        "sourcepkg": "sourctest",
                        "files": [
                            "file1",
                        ],
                        "location": "/hey/there",
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "zlib",
                        "version": "1.2.11-r3",
                    },
                    "expected": {
                        "type": "npm",
                        "name": "zlib",
                        "versions": ["1.2.11-r3"],
                        "latest": "1.2.11-r3",
                        "origins": [],
                        "lics": [],
                        "sourcepkg": "zlib",
                        "files": [],
                        "location": "/virtual/npmpkg/zlib-1.2.11-r3",
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = NPMHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]


class TestJavaHint:
    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "pkg": {
                        "name": "spring-core",
                        "version": "1.0.0",
                        "origin": "Apache Software Foundation",
                        "location": "/hey/there",
                        "metadata": {"hey": "there"},
                    },
                    "expected": {
                        "type": "java-jar",
                        "name": "spring-core",
                        "specification-version": "1.0.0",
                        "implementation-version": "1.0.0",
                        "maven-version": "1.0.0",
                        "origin": "Apache Software Foundation",
                        "location": "/hey/there",
                        "metadata": {"hey": "there"},
                    },
                    "expected_error": "",
                },
                id="all-fields",
            ),
            pytest.param(
                {
                    "pkg": {},
                    "expected": {},
                    "expected_error": "bad hints record, all hints records must supply at least a name, version and type",
                },
                id="no-fields",
            ),
            pytest.param(
                {
                    "pkg": {
                        "name": "spring-core",
                        "version": "1.0.0",
                    },
                    "expected": {
                        "type": "java-jar",
                        "name": "spring-core",
                        "implementation-version": "1.0.0",
                        "specification-version": "1.0.0",
                        "maven-version": "1.0.0",
                        "origin": "",
                        "location": "/virtual/javapkg/spring-core-1.0.0.jar",
                        "metadata": {},
                    },
                    "expected_error": "",
                },
                id="required-fields-only",
            ),
        ],
    )
    def test_to_dict(self, param):
        hint = JavaHint(param["pkg"])

        if param["expected_error"]:
            with pytest.raises(HintsTypeError, match=r"%s" % param["expected_error"]):
                hint.to_dict()
        else:
            assert hint.to_dict() == param["expected"]
