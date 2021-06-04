import json
import pytest

from anchore_engine.clients.grype_wrapper import (
    GrypeVulnerability,
    GrypeVulnerabilityMetadata,
)
from anchore_engine.services.policy_engine.engine.vulns.mappers import (
    GRYPE_PACKAGE_MAPPERS,
    GRYPE_DISTRO_MAPPERS,
    ENGINE_PACKAGE_MAPPERS,
    ENGINE_DISTRO_MAPPERS,
    EngineGrypeDBMapper,
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


def mock_raw_grype_vulnerability(
    id=None,
    cvss="[]",
    description=None,
    urls="[]",
    record_source=None,
    severity=None,
    cpes=None,
    fixed_in_version=None,
    namespace=None,
    package_name=None,
    related_vulnerabilities="[]",
    metadata_record_source=None,
    version_constraint=None,
    version_format=None,
):
    vulnerability_metadata = GrypeVulnerabilityMetadata()
    vulnerability_metadata.id = id
    vulnerability_metadata.cvss = cvss
    vulnerability_metadata.description = description
    vulnerability_metadata.urls = urls
    vulnerability_metadata.record_source = record_source
    vulnerability_metadata.severity = severity

    vulnerability = GrypeVulnerability()
    vulnerability.id = id
    vulnerability.cpes = cpes
    vulnerability.fixed_in_version = fixed_in_version
    vulnerability.namespace = namespace
    vulnerability.package_name = package_name
    vulnerability.proxy_vulnerabilities = related_vulnerabilities
    vulnerability.record_source = metadata_record_source
    vulnerability.version_constraint = version_constraint
    vulnerability.version_format = version_format
    vulnerability_metadata.vulnerability = vulnerability

    return vulnerability_metadata


# TODO Replace this with more atomic tests, once the method under test has been decomposed.
# Current approach was only useful for early local dev
@pytest.mark.parametrize(
    "id, cvss, description, urls, record_source, severity, cpes, fixed_in_version, namespace, package_name, related_vulnerabilities, metadata_record_source, version_constraint, version_format",
    [
        (
            "CVE-1234",
            '[{"VendorMetadata":null,"Metrics":{"BaseScore":4,"ExploitabilityScore":8,"ImpactScore":2.9},"Vector":"AV:N/AC:L/Au:S/C:N/I:P/A:N","Version":"2.0"},{"VendorMetadata":null,"Metrics":{"BaseScore":6.5,"ExploitabilityScore":2.8,"ImpactScore":3.6},"Vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N","Version":"3.1"}]',
            "Description for the vulnerability.",
            "[]",
            "nvd",
            None,
            None,
            None,
            None,
            None,
            "[]",
            None,
            None,
            None,
        ),
    ],
)
def test_to_engine_vulnerability(
    id,
    cvss,
    description,
    urls,
    record_source,
    severity,
    cpes,
    fixed_in_version,
    namespace,
    package_name,
    related_vulnerabilities,
    metadata_record_source,
    version_constraint,
    version_format,
):
    input_raw_grype_vulnerability = mock_raw_grype_vulnerability(
        id,
        cvss,
        description,
        urls,
        record_source,
        severity,
        cpes,
        fixed_in_version,
        namespace,
        package_name,
        related_vulnerabilities,
        metadata_record_source,
        version_constraint,
        version_format,
    )

    result = EngineGrypeDBMapper()._to_engine_vulnerability(
        input_raw_grype_vulnerability
    )

    assert result is not None
    assert result["id"] == id
    assert result["description"] == description
    assert result["severity"] == severity
    assert result["namespace"] == namespace

    links_deserialized = json.loads(urls)
    if links_deserialized == []:
        assert result["link"] == links_deserialized
    else:
        assert result["link"] == links_deserialized[0]

    # TODO Update this once mapped properly
    assert result["references"] is None

    # expected_cvss_dict = {
    #     "id": id,
    #     "cvss_v2": json.loads(cvss_v2),
    #     "cvss_v3": json.loads(cvss_v3),
    # }

    if record_source is not None and record_source.startswith("nvdv2"):
        assert len(result["nvd_data"]) == 1
        # assert expected_cvss_dict == result["nvd_data"][0]
        assert result["vendor_data"] == []
    else:
        assert result["nvd_data"] == []
        assert len(result["vendor_data"]) == 1
        # assert expected_cvss_dict == result["vendor_data"][0]

    assert result["affected_packages"] is not None
    assert len(result["affected_packages"]) == 1
    assert result["affected_packages"][0]["name"] == package_name
    assert result["affected_packages"][0]["type"] == version_format
    assert result["affected_packages"][0]["version"] == version_constraint
