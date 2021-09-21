import pytest

from anchore_engine.services.policy_engine.engine.vulns.mappers import (
    ENGINE_DISTRO_MAPPERS,
    ENGINE_PACKAGE_MAPPERS,
    GRYPE_PACKAGE_MAPPERS,
)


@pytest.mark.parametrize(
    "test_distro, expected_os, expected_like_os",
    [
        pytest.param("rhel", "redhat", "fedora", id="rhel"),
        pytest.param("amzn", "amazonlinux", "fedora", id="amazonlinux"),
        pytest.param("ol", "oraclelinux", "fedora", id="oraclelinux"),
        pytest.param("centos", "centos", "fedora", id="centos"),
        pytest.param("debian", "debian", "debian", id="debian"),
        pytest.param("ubuntu", "ubuntu", "debian", id="ubuntu"),
        pytest.param("alpine", "alpine", "alpine", id="alpine"),
        pytest.param("sles", "sles", "sles", id="sles"),
        pytest.param("windows", "windows", "", id="windows"),
    ],
)
def test_engine_distro_mappers(test_distro, expected_os, expected_like_os):
    mapper = ENGINE_DISTRO_MAPPERS.get(test_distro)
    assert mapper.grype_os == expected_os
    assert mapper.grype_like_os == expected_like_os
    assert mapper.to_grype_distro("0") == {
        "name": expected_os,
        "version": "0",
        "idLike": expected_like_os,
    }


@pytest.mark.parametrize(
    "test_type, expected_type",
    [
        pytest.param("java", "java-archive", id="java"),
        pytest.param("APKG", "apk", id="apkg"),
        pytest.param("dpkg", "deb", id="dpkg"),
        pytest.param("kb", "msrc-kb", id="msrc-kb"),
    ],
)
def test_engine_package_mappers(test_type, expected_type):
    mapper = ENGINE_PACKAGE_MAPPERS.get(test_type)
    assert mapper.grype_type == expected_type


@pytest.mark.parametrize(
    "test_type, expected_type",
    [
        pytest.param("jenkins-plugin", "java", id="jenkins"),
        pytest.param("java-archive", "java", id="java"),
        pytest.param("deb", "dpkg", id="dpkg"),
        pytest.param("apk", "APKG", id="apkg"),
        pytest.param("msrc-kb", "kb", id="msrc-kb"),
    ],
)
def test_grype_package_mappers(test_type, expected_type):
    mapper = GRYPE_PACKAGE_MAPPERS.get(test_type)
    assert mapper.engine_type == expected_type


class TestImageContentAPIToGrypeSbom:
    @pytest.mark.parametrize(
        "mapper, test_input, expected",
        [
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("npm"),
                {
                    "cpes": [
                        "cpe:2.3:a:lodash:lodash:4.17.4:*:*:*:*:*:*:*",
                        "cpe:2.3:a:*:lodash:4.17.4:*:*:*:*:*:*:*",
                    ],
                    "license": "MIT",
                    "licenses": ["MIT"],
                    "location": "/node_modules/lodash/package.json",
                    "origin": "John-David Dalton <john.david.dalton@gmail.com> (http://allyoucanleet.com/)",
                    "package": "lodash",
                    "type": "NPM",
                    "version": "4.17.4",
                },
                {
                    "name": "lodash",
                    "type": "npm",
                    "language": "javascript",
                    "locations": [{"path": "/node_modules/lodash/package.json"}],
                    "cpes": [
                        "cpe:2.3:a:*:lodash:4.17.4:*:*:*:*:*:*:*",
                        "cpe:2.3:a:lodash:lodash:4.17.4:*:*:*:*:*:*:*",
                    ],
                    "version": "4.17.4",
                },
                id="npm",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("gem"),
                {
                    "cpes": [
                        "cpe:2.3:a:jessica-lynn-suttles:bundler:2.1.4:*:*:*:*:*:*:*",
                        "cpe:2.3:a:jessica_lynn_suttles:bundler:2.1.4:*:*:*:*:*:*:*",
                    ],
                    "license": "MIT",
                    "licenses": ["MIT"],
                    "location": "/usr/lib/ruby/gems/2.7.0/specifications/bundler-2.1.4.gemspec",
                    "origin": "...",
                    "package": "bundler",
                    "type": "GEM",
                    "version": "2.1.4",
                },
                {
                    "name": "bundler",
                    "type": "gem",
                    "language": "ruby",
                    "locations": [
                        {
                            "path": "/usr/lib/ruby/gems/2.7.0/specifications/bundler-2.1.4.gemspec"
                        }
                    ],
                    "cpes": [
                        "cpe:2.3:a:jessica_lynn_suttles:bundler:2.1.4:*:*:*:*:*:*:*",
                        "cpe:2.3:a:jessica-lynn-suttles:bundler:2.1.4:*:*:*:*:*:*:*",
                    ],
                    "version": "2.1.4",
                },
                id="gem",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("python"),
                {
                    "cpes": [
                        "cpe:2.3:a:python-pip:pip:21.2.2:*:*:*:*:*:*:*",
                        "cpe:2.3:a:python:pip:21.2.2:*:*:*:*:*:*:*",
                        "cpe:2.3:a:pip:pip:21.2.2:*:*:*:*:*:*:*",
                    ],
                    "license": "MIT",
                    "licenses": ["MIT"],
                    "location": "/usr/local/lib/python3.9/site-packages/pip",
                    "origin": "The pip developers <distutils-sig@python.org>",
                    "package": "pip",
                    "type": "PYTHON",
                    "version": "21.2.2",
                },
                {
                    "name": "pip",
                    "version": "21.2.2",
                    "type": "python",
                    "cpes": [
                        "cpe:2.3:a:python-pip:pip:21.2.2:*:*:*:*:*:*:*",
                        "cpe:2.3:a:python:pip:21.2.2:*:*:*:*:*:*:*",
                        "cpe:2.3:a:pip:pip:21.2.2:*:*:*:*:*:*:*",
                    ],
                    "language": "python",
                    "locations": [
                        {"path": "/usr/local/lib/python3.9/site-packages/pip"}
                    ],
                },
                id="python",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("dpkg"),
                {
                    "cpes": ["cpe:2.3:a:bsdutils:bsdutils:1:2.33.1-0.1:*:*:*:*:*:*:*"],
                    "license": "BSD-2-clause BSD-3-clause BSD-4-clause GPL-2 GPL-2+ GPL-3 GPL-3+ LGPL LGPL-2 LGPL-2+ LGPL-2.1 LGPL-2.1+ LGPL-3 LGPL-3+ MIT public-domain",
                    "licenses": [
                        "BSD-2-clause",
                    ],
                    "origin": "LaMont Jones <lamont@debian.org> (maintainer)",
                    "package": "bsdutils",
                    "size": "293000",
                    "sourcepkg": "util-linux",
                    "type": "dpkg",
                    "version": "1:2.33.1-0.1",
                },
                {
                    "name": "bsdutils",
                    "version": "1:2.33.1-0.1",
                    "type": "deb",
                    "cpes": ["cpe:2.3:a:bsdutils:bsdutils:1:2.33.1-0.1:*:*:*:*:*:*:*"],
                    "locations": [{"path": "pkgdb"}],
                    "metadataType": "DpkgMetadata",
                    "metadata": {"source": "util-linux"},
                },
                id="dpkg-with-source",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("APKG"),
                {
                    "cpes": [
                        "cpe:2.3:a:ssl-client:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl_client:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl-client:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl_client:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                    ],
                    "license": "GPL-2.0-only",
                    "licenses": ["GPL-2.0-only"],
                    "origin": "Natanael Copa <ncopa@alpinelinux.org>",
                    "package": "ssl_client",
                    "size": "28672",
                    "sourcepkg": "busybox",
                    "type": "APKG",
                    "version": "1.32.1-r5",
                },
                {
                    "name": "ssl_client",
                    "version": "1.32.1-r5",
                    "type": "apk",
                    "cpes": [
                        "cpe:2.3:a:ssl-client:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl_client:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl-client:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl_client:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl:ssl_client:1.32.1-r5:*:*:*:*:*:*:*",
                        "cpe:2.3:a:ssl:ssl-client:1.32.1-r5:*:*:*:*:*:*:*",
                    ],
                    "locations": [{"path": "pkgdb"}],
                    "metadataType": "ApkgMetadata",
                    "metadata": {"originPackage": "busybox"},
                },
                id="apkg-with-source",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("kb"),
                {
                    "cpes": None,
                    "license": "Unknown",
                    "licenses": ["Unknown"],
                    "origin": "Microsoft",
                    "package": "935509",
                    "size": "0",
                    "sourcepkg": "10855",
                    "type": "kb",
                    "version": "935509",
                },
                {
                    "name": "10855",
                    "version": "935509",
                    "type": "msrc-kb",
                    "locations": [{"path": "registry"}],
                },
                id="microsoft-kb",
            ),
        ],
    )
    def test_mappers(self, mapper, test_input, expected):
        actual = mapper.image_content_to_grype_sbom(test_input)

        # sort the list attributes before comparing
        actual = {
            key: sorted(value) if isinstance(value, list) else value
            for key, value in actual.items()
        }
        expected = {
            key: sorted(value) if isinstance(value, list) else value
            for key, value in expected.items()
        }

        assert actual.pop("id")
        assert actual == expected
