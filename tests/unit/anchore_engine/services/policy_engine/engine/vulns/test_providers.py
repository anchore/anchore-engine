import json
import pytest

from anchore_engine.clients.grype_wrapper import (
    GrypeVulnerability,
    GrypeVulnerabilityMetadata,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import GrypeProvider
from unittest import TestCase


def mock_raw_grype_vulnerability(
    id=None,
    cvss_v2="{}",
    cvss_v3="{}",
    description=None,
    links="[]",
    record_source=None,
    severity=None,
    cpes=None,
    fixed_in_version=None,
    namespace=None,
    package_name=None,
    proxy_vulnerabilities="[]",
    metadata_record_source=None,
    version_constraint=None,
    version_format=None,
):
    vulnerability_metadata = GrypeVulnerabilityMetadata()
    vulnerability_metadata.id = id
    vulnerability_metadata.cvss_v2 = cvss_v2
    vulnerability_metadata.cvss_v3 = cvss_v3
    vulnerability_metadata.description = description
    vulnerability_metadata.links = links
    vulnerability_metadata.record_source = record_source
    vulnerability_metadata.severity = severity

    vulnerability = GrypeVulnerability()
    vulnerability.id = id
    vulnerability.cpes = cpes
    vulnerability.fixed_in_version = fixed_in_version
    vulnerability.namespace = namespace
    vulnerability.package_name = package_name
    vulnerability.proxy_vulnerabilities = proxy_vulnerabilities
    vulnerability.record_source = metadata_record_source
    vulnerability.version_constraint = version_constraint
    vulnerability.version_format = version_format
    vulnerability_metadata.vulnerability = vulnerability

    return vulnerability_metadata


# TODO Add a real test matrix
@pytest.mark.parametrize(
    "id, cvss_v2, cvss_v3, description, links, record_source, severity, cpes, fixed_in_version, namespace, package_name, proxy_vulnerabilities, metadata_record_source, version_constraint, version_format",
    [
        (
            "CVE-1234",
            '{"BaseScore": 5.5, "ExploitabilityScore": 8, "ImpactScore": 4.9, "Vector": "AV:N/AC:L/Au:S/C:N/I:P/A:P"}',
            '{"BaseScore": 6.5, "ExploitabilityScore": 2.8, "ImpactScore": 3.6, "Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"}',
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
def test_transform_grype_vulnerability(
    id,
    cvss_v2,
    cvss_v3,
    description,
    links,
    record_source,
    severity,
    cpes,
    fixed_in_version,
    namespace,
    package_name,
    proxy_vulnerabilities,
    metadata_record_source,
    version_constraint,
    version_format,
):
    input_raw_grype_vulnerability = mock_raw_grype_vulnerability(
        id,
        cvss_v2,
        cvss_v3,
        description,
        links,
        record_source,
        severity,
        cpes,
        fixed_in_version,
        namespace,
        package_name,
        proxy_vulnerabilities,
        metadata_record_source,
        version_constraint,
        version_format,
    )

    result = GrypeProvider._transform_grype_vulnerability(input_raw_grype_vulnerability)

    assert result is not None
    assert result["id"] == id
    assert result["description"] == description
    assert result["severity"] == severity
    assert result["namespace"] == namespace

    links_deserialized = json.loads(links)
    if links_deserialized == []:
        assert result["link"] == links_deserialized
    else:
        assert result["link"] == links_deserialized[0]

    # TODO Update this once mapped properly
    assert result["references"] is None

    expected_cvss_dict = {
        "id": id,
        "cvss_v2": json.loads(cvss_v2),
        "cvss_v3": json.loads(cvss_v3),
    }

    if record_source is not None and record_source.startswith("nvdv2"):
        assert len(result["nvd_data"]) == 1
        TestCase().assertDictEqual(expected_cvss_dict, result["nvd_data"][0])
        assert result["vendor_data"] == []
    else:
        assert result["nvd_data"] == []
        assert len(result["vendor_data"]) == 1
        TestCase().assertDictEqual(expected_cvss_dict, result["vendor_data"][0])

    assert result["affected_packages"] is not None
    assert len(result["affected_packages"]) == 1
    assert result["affected_packages"][0]["name"] == package_name
    assert result["affected_packages"][0]["type"] == version_format
    assert result["affected_packages"][0]["version"] == version_constraint
