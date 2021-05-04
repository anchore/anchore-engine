import json
import pytest

from anchore_engine.clients.grype_wrapper import (
    GrypeVulnerabilityMetadata,
    GrypeVulnerability,
)
from anchore_engine.services.apiext.api.controllers import query


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


@pytest.mark.parametrize(
    "id, cvss_v2, cvss_v3, description, links, record_source, severity, cpes, fixed_in_version, namespace, package_name, proxy_vulnerabilities, metadata_record_source, version_constraint, version_format",
    [
        (
            "CVE-1234",
            "{}",
            "{}",
            None,
            "[]",
            None,
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

    result = query.transform_grype_vulnerability(input_raw_grype_vulnerability)

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

    # TODO Update these once mapped properly
    assert result["references"] is None
    assert result["nvd_data"] == []
    assert result["vendor_data"] == []

    assert result["affected_packages"] is not None
    assert len(result["affected_packages"]) == 1
    assert result["affected_packages"][0]["name"] == package_name
    assert result["affected_packages"][0]["type"] == version_format
    assert result["affected_packages"][0]["version"] == version_constraint
