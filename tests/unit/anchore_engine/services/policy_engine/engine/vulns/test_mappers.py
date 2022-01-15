import pytest

from anchore_engine.common.models.policy_engine import NVDReference
from anchore_engine.services.policy_engine.engine.vulns.mappers import (
    ENGINE_DISTRO_MAPPERS,
    ENGINE_PACKAGE_MAPPERS,
    GRYPE_PACKAGE_MAPPERS,
    EngineGrypeDBMapper,
    JavaMapper,
    VulnerabilityMapper,
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
        pytest.param("rocky", "rockylinux", "fedora", id="rocky"),
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


class TestJavaMapper:
    @pytest.mark.parametrize(
        "input_metadata, expected_output",
        [
            (
                {
                    "pom.properties": "\ngroupId=org.yaml\nartifactId=snakeyaml\nversion=\n"
                },
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "groupId": "org.yaml",
                        "version": "",
                    }
                },
            ),
            (
                {
                    "pom.properties": "groupId=org.yaml\nartifactId=snakeyaml\nversion=1.18"
                },
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "groupId": "org.yaml",
                        "version": "1.18",
                    }
                },
            ),
            (
                {
                    "pom.properties": {
                        "artifactId": "snakeyaml",
                        "groupId": "org.yaml",
                        "version": "1.18",
                    }
                },
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "groupId": "org.yaml",
                        "version": "1.18",
                    }
                },
            ),
            (
                {
                    "pom.properties": "\ngroupId=org.yaml\nartifactId=snakeyaml\nversion=1.18\n",
                    "someProperty": "someValue",
                },
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "groupId": "org.yaml",
                        "version": "1.18",
                    },
                },
            ),
            (
                {"pom.properties": "\ngroupId\nartifactId=snakeyaml\nversion=1.18\n"},
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "groupId": "",
                        "version": "1.18",
                    }
                },
            ),
            (
                {"pom.properties": "\norg.yaml\nartifactId=snakeyaml\nversion=1.18\n"},
                {
                    "pomProperties": {
                        "artifactId": "snakeyaml",
                        "org.yaml": "",
                        "version": "1.18",
                    }
                },
            ),
        ],
    )
    def test_image_content_to_grype_metadata(self, input_metadata, expected_output):
        # Function under test
        result = JavaMapper._image_content_to_grype_metadata(input_metadata)

        # Validate result
        assert result == expected_output


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
                ENGINE_PACKAGE_MAPPERS.get("java"),
                {
                    "cpes": [
                        "cpe:2.3:a:amqp-client:amqp_client:5.9.0:*:*:*:*:*:*:*",
                        "cpe:2.3:a:amqp_client:amqp_client:5.9.0:*:*:*:*:*:*:*",
                    ],
                    "implementation-version": "N/A",
                    "location": "/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/march_hare-4.3.0-java/lib/ext/rabbitmq-client.jar:amqp-client",
                    "maven-version": "5.9.0",
                    "metadata": {
                        "pom.properties": "\ngroupId=com.rabbitmq\nartifactId=amqp-client\nversion=5.9.0\n"
                    },
                    "origin": "com.rabbitmq",
                    "package": "amqp-client",
                    "specification-version": "N/A",
                    "type": "JAVA-JAR",
                    "version": "5.9.0",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:amqp-client:amqp_client:5.9.0:*:*:*:*:*:*:*",
                        "cpe:2.3:a:amqp_client:amqp_client:5.9.0:*:*:*:*:*:*:*",
                    ],
                    "language": "java",
                    "locations": [
                        {
                            "path": "/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/march_hare-4.3.0-java/lib/ext/rabbitmq-client.jar:amqp-client"
                        }
                    ],
                    "metadata": {
                        "pomProperties": {
                            "artifactId": "amqp-client",
                            "groupId": "com.rabbitmq",
                            "version": "5.9.0",
                        }
                    },
                    "metadataType": "JavaMetadata",
                    "name": "amqp-client",
                    "type": "java-archive",
                    "version": "5.9.0",
                },
                id="java",
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
                    "metadataType": "ApkMetadata",
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
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("rpm"),
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "license": "OpenSSL and ASL 2.0",
                    "licenses": ["OpenSSL", "and", "ASL", "2.0"],
                    "origin": "Red Hat, Inc.",
                    "package": "openssl-libs",
                    "size": "3757208",
                    "sourcepkg": "openssl-1.1.1g-15.el8_3.src.rpm",
                    "type": "rpm",
                    "version": "1:1.1.1g-15.el8_3",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "rpm",
                    "locations": [{"path": "pkgdb"}],
                    "version": "1:1.1.1g-15.el8_3",
                    "metadataType": "RpmdbMetadata",
                    "metadata": {
                        "sourceRpm": "openssl-1.1.1g-15.el8_3.src.rpm",
                        "epoch": 1,
                    },
                },
                id="rpm-with-epoch",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("rpm"),
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "license": "OpenSSL and ASL 2.0",
                    "licenses": ["OpenSSL", "and", "ASL", "2.0"],
                    "origin": "Red Hat, Inc.",
                    "package": "openssl-libs",
                    "size": "3757208",
                    "sourcepkg": "openssl-1.1.1g-15.el8_3.src.rpm",
                    "type": "rpm",
                    "version": "1.1.1g-15.el8_3",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "rpm",
                    "locations": [{"path": "pkgdb"}],
                    "version": "1.1.1g-15.el8_3",
                    "metadataType": "RpmdbMetadata",
                    "metadata": {
                        "sourceRpm": "openssl-1.1.1g-15.el8_3.src.rpm",
                        "epoch": None,
                    },
                },
                id="rpm-no-epoch",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("rpm"),
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "license": "OpenSSL and ASL 2.0",
                    "licenses": ["OpenSSL", "and", "ASL", "2.0"],
                    "origin": "Red Hat, Inc.",
                    "package": "openssl-libs",
                    "size": "3757208",
                    "sourcepkg": None,
                    "type": "rpm",
                    "version": "1.1.1g-15.el8_3",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "rpm",
                    "locations": [{"path": "pkgdb"}],
                    "version": "1.1.1g-15.el8_3",
                    "metadataType": "RpmdbMetadata",
                    "metadata": {
                        "sourceRpm": None,
                        "epoch": None,
                    },
                },
                id="rpm-no-src",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("rpm"),
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "license": "OpenSSL and ASL 2.0",
                    "licenses": ["OpenSSL", "and", "ASL", "2.0"],
                    "origin": "Red Hat, Inc.",
                    "package": "openssl-libs",
                    "size": "3757208",
                    "sourcepkg": None,
                    "type": "rpm",
                    "version": "1:1.1.1g-15.el8_3",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:openssl-libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl-libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl_libs:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:openssl:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl-libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                        "cpe:2.3:a:redhat:openssl_libs:1.1.1g-15.el8_3:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "rpm",
                    "locations": [{"path": "pkgdb"}],
                    "version": "1:1.1.1g-15.el8_3",
                    "metadataType": "RpmdbMetadata",
                    "metadata": {
                        "sourceRpm": None,
                        "epoch": 1,
                    },
                },
                id="rpm-no-src-but-epoch",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("go"),
                {
                    "cpes": [],
                    "package": "openssl-libs",
                    "type": "go",
                    "version": "1.1.1",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:*:openssl-libs:1.1.1:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "go-module",
                    "language": "go",
                    "version": "1.1.1",
                },
                id="go-mod-no-cpes",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("go"),
                {
                    "cpes": [
                        "cpe:2.3:a:myvendor:openssl-libs:1.1.1-a:*:*:*:*:*:*:*",
                    ],
                    "package": "openssl-libs",
                    "type": "go",
                    "version": "1.1.1",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:myvendor:openssl-libs:1.1.1-a:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "go-module",
                    "language": "go",
                    "version": "1.1.1",
                },
                id="go-mod-with-cpes",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("binary"),
                {
                    "cpes": [],
                    "package": "openssl-libs",
                    "type": "go",
                    "version": "1.1.1",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:*:openssl-libs:1.1.1:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "binary",
                    "language": "",
                    "version": "1.1.1",
                },
                id="binary-no-cpes",
            ),
            pytest.param(
                ENGINE_PACKAGE_MAPPERS.get("binary"),
                {
                    "cpes": [
                        "cpe:2.3:a:myvendor:openssl-libs:1.1.1-a:*:*:*:*:*:*:*",
                    ],
                    "package": "openssl-libs",
                    "type": "go",
                    "version": "1.1.1",
                },
                {
                    "cpes": [
                        "cpe:2.3:a:myvendor:openssl-libs:1.1.1-a:*:*:*:*:*:*:*",
                    ],
                    "name": "openssl-libs",
                    "type": "binary",
                    "language": "",
                    "version": "1.1.1",
                },
                id="binary-with-cpes",
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


class TestVulnerabilityMapper:
    @pytest.mark.parametrize(
        "vuln_id,feed_group,nvd_refs,expected",
        [
            pytest.param("foobar", "vulndb:xyz", None, "foobar", id="none-nvd-refs"),
            pytest.param(None, None, None, None, id="all-none"),
            pytest.param("foobar", "vulndb:xyz", [], "foobar", id="no-nvd-refs"),
            pytest.param(
                "foobar", "vulndb:xyz", ["1"], "foobar", id="invalid-nvd-refs"
            ),
            pytest.param("foobar", None, [], "foobar", id="none-feed-group"),
            pytest.param("foobar", 1, [], "foobar", id="invalid-feed-group-int"),
            pytest.param(
                "foobar", ["x", "y"], None, "foobar", id="invalid-feed-group-list"
            ),
            pytest.param(
                "foobar",
                "abc:xyz",
                [NVDReference(vulnerability_id="CVE-xyz")],
                "foobar",
                id="valid-dont-transform",
            ),
            pytest.param(
                "foobar",
                "vulndb",
                [NVDReference(vulnerability_id="CVE-xyz")],
                "CVE-xyz",
                id="valid-transform",
            ),
            pytest.param(
                "foobar",
                "vulndb",
                [
                    NVDReference(vulnerability_id="CVE-xyz"),
                    NVDReference(vulnerability_id="CVE-pqr"),
                ],
                "foobar",
                id="valid-multiple-nvd-refs",
            ),
        ],
    )
    def test_get_normalized_vulnerability_id(
        self, vuln_id, feed_group, nvd_refs, expected
    ):
        assert (
            VulnerabilityMapper._try_get_normalized_vulnerability_id(
                vuln_id, feed_group, nvd_refs
            )
            == expected
        )

    @pytest.mark.parametrize(
        "vuln_id,url,expected",
        [
            pytest.param(
                "foobar",
                None,
                "http://<valid endpoint not found>/query/vulnerabilities?id=foobar",
                id="none-url",
            ),
            pytest.param(
                "foobar",
                "",
                "http://<valid endpoint not found>/query/vulnerabilities?id=foobar",
                id="blank-url",
            ),
        ],
    )
    def test_try_make_link(self, vuln_id, url, expected):
        assert VulnerabilityMapper._try_make_link(vuln_id, url) == expected


class TestEngineGrypeDBMapper:
    @pytest.mark.parametrize(
        "cvss_dict, expected",
        [
            pytest.param(
                {
                    "VendorMetadata": None,
                    "Metrics": {
                        "BaseScore": 7.8,
                        "ExploitabilityScore": 10,
                        "ImpactScore": 6.9,
                    },
                    "Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                    "Version": "2.0",
                },
                {
                    "version": "2.0",
                    "vector_string": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                    "severity": "High",
                    "base_metrics": {
                        "base_score": 7.8,
                        "expolitability_score": 10,
                        "impact_score": 6.9,
                    },
                },
                id="nvd-cvss-2",
            ),
            pytest.param(
                {
                    "VendorMetadata": None,
                    "Metrics": {
                        "BaseScore": 7.5,
                        "ExploitabilityScore": 3.9,
                        "ImpactScore": 3.6,
                    },
                    "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "Version": "3.1",
                },
                {
                    "version": "3.1",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "severity": "High",
                    "base_metrics": {
                        "base_score": 7.5,
                        "expolitability_score": 3.9,
                        "impact_score": 3.6,
                    },
                },
                id="nvd-cvss-3",
            ),
            pytest.param(
                {
                    "VendorMetadata": {
                        "access_complexity": "LOW",
                        "access_vector": "NETWORK",
                        "authentication": "NONE",
                        "availability_impact": "NONE",
                        "base_score": 5,
                        "confidentiality_impact": "NONE",
                        "exploitability_score": 10,
                        "impact_score": 2.9,
                        "integrity_impact": "PARTIAL",
                    },
                    "Metrics": {
                        "BaseScore": 5,
                        "ExploitabilityScore": 10,
                        "ImpactScore": 2.9,
                    },
                    "Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                    "Version": "2.0",
                },
                {
                    "version": "2.0",
                    "vector_string": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
                    "severity": "Medium",
                    "base_metrics": {
                        "base_score": 5,
                        "expolitability_score": 10,
                        "impact_score": 2.9,
                    },
                },
                id="third-party-cvss-2",
            ),
            pytest.param(
                {
                    "VendorMetadata": {"BaseSeverity": "High", "Status": "verified"},
                    "Metrics": {
                        "BaseScore": 7.5,
                        "ExploitabilityScore": 3.9,
                        "ImpactScore": 3.6,
                    },
                    "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "Version": "3.1",
                },
                {
                    "version": "3.1",
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "severity": "High",
                    "base_metrics": {
                        "base_score": 7.5,
                        "expolitability_score": 3.9,
                        "impact_score": 3.6,
                    },
                },
                id="rhel-cvss-3",
            ),
        ],
    )
    def test_transform_cvss_score(self, cvss_dict, expected):
        assert EngineGrypeDBMapper()._transform_cvss_score(cvss_dict) == expected

    @pytest.mark.parametrize(
        "vuln_id, cvss_dict, expected",
        [
            pytest.param(
                "CVE-xyz",
                {
                    "VendorMetadata": None,
                    "Metrics": {
                        "BaseScore": 7.8,
                        "ExploitabilityScore": 10,
                        "ImpactScore": 6.9,
                    },
                    "Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                    "Version": "2.0",
                },
                {
                    "cvss_v2": {
                        "version": "2.0",
                        "vector_string": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                        "severity": "High",
                        "base_metrics": {
                            "base_score": 7.8,
                            "expolitability_score": 10,
                            "impact_score": 6.9,
                        },
                    },
                    "cvss_v3": None,
                    "id": "CVE-xyz",
                },
                id="nvd-cvss-2",
            ),
            pytest.param(
                "CVE-abc",
                {
                    "VendorMetadata": None,
                    "Metrics": {
                        "BaseScore": 7.5,
                        "ExploitabilityScore": 3.9,
                        "ImpactScore": 3.6,
                    },
                    "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "Version": "3.1",
                },
                {
                    "cvss_v2": None,
                    "cvss_v3": {
                        "version": "3.1",
                        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "severity": "High",
                        "base_metrics": {
                            "base_score": 7.5,
                            "expolitability_score": 3.9,
                            "impact_score": 3.6,
                        },
                    },
                    "id": "CVE-abc",
                },
                id="nvd-cvss-3",
            ),
        ],
    )
    def test_transform_cvss(self, vuln_id, cvss_dict, expected):
        assert EngineGrypeDBMapper()._transform_cvss(vuln_id, cvss_dict) == expected

    @pytest.mark.parametrize(
        "urls, expected",
        [
            pytest.param("a.b.c", [], id="invalid-string"),
            pytest.param(None, [], id="invalid-none"),
            pytest.param([], [], id="invalid-empty"),
            pytest.param(
                ["a.b.c"], [{"url": "a.b.c", "source": "N/A"}], id="valid-single"
            ),
            pytest.param(
                ["a.b.c", "x.y.z"],
                [{"url": "a.b.c", "source": "N/A"}, {"url": "x.y.z", "source": "N/A"}],
                id="valid-multiple",
            ),
        ],
    )
    def test__transform_urls(self, urls, expected):
        assert EngineGrypeDBMapper._transform_urls(urls) == expected
