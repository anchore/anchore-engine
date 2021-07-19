import pytest

from anchore_engine.services.policy_engine.engine.vulns.mappers import (
    ENGINE_DISTRO_MAPPERS,
    ENGINE_PACKAGE_MAPPERS,
    GRYPE_DISTRO_MAPPERS,
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
        pytest.param("alpine", "alpine", "alpine", id="ubuntu"),
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
    "test_os, expected_distro",
    [
        pytest.param("redhat", "rhel", id="rhel"),
        pytest.param("amazonlinux", "amzn", id="amazonlinux"),
        pytest.param("oraclelinux", "ol", id="oraclelinux"),
        pytest.param("centos", "centos", id="centos"),
        pytest.param("debian", "debian", id="debian"),
        pytest.param("ubuntu", "ubuntu", id="ubuntu"),
        pytest.param("alpine", "alpine", id="ubuntu"),
    ],
)
def test_grype_distro_mappers(test_os, expected_distro):
    mapper = GRYPE_DISTRO_MAPPERS.get(test_os)
    assert mapper.engine_distro == expected_distro


@pytest.mark.parametrize(
    "test_type, expected_type",
    [
        pytest.param("java", "java-archive", id="java"),
        pytest.param("APKG", "apk", id="apkg"),
        pytest.param("dpkg", "deb", id="dpkg"),
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
    ],
)
def test_grype_package_mappers(test_type, expected_type):
    mapper = GRYPE_PACKAGE_MAPPERS.get(test_type)
    assert mapper.engine_type == expected_type
