from dataclasses import asdict

import pytest

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from tests.functional.services.policy_engine.utils.utils import (
    VulnerabilityQuery,
    VulnerabilityQueryMetadata,
)
from tests.functional.services.utils import http_utils


# Series of tests that verify expected vulnerability query results based upon set of vulns seeded into database.
class TestQueryVulnerabilities:
    @pytest.mark.parametrize(
        "query",
        [
            VulnerabilityQuery(["CVE-2017-7245"], "single_cve"),
            VulnerabilityQuery(
                ["CVE-2017-7245", "CVE-2014-4617", "CVE-2018-5709"], "multiple_cves"
            ),
            VulnerabilityQuery(
                ["CVE-2017-7245"],
                "single_cve_filter_affected_package",
                VulnerabilityQueryMetadata(affected_package="pcre3"),
            ),
            VulnerabilityQuery(
                ["CVE-2017-7245", "CVE-2017-11164"],
                "multiple_cves_filter_affected_package",
                VulnerabilityQueryMetadata(affected_package="pcre3"),
            ),
            VulnerabilityQuery(
                ["CVE-2017-7245"],
                "single_cve_multiple_filters",
                VulnerabilityQueryMetadata(
                    affected_package="pcre3", namespace="debian:10"
                ),
            ),
            VulnerabilityQuery(
                ["CVE-2017-18018"],
                "single_cve_multiple_filters_2",
                VulnerabilityQueryMetadata(
                    affected_package="coreutils",
                    namespace="nvdv2:cves",
                    affected_package_version="8.9",
                ),
            ),
            VulnerabilityQuery(
                ["CVE-2017-7245", "CVE-2017-11164"],
                "multiple_cves_multiple_filters",
                VulnerabilityQueryMetadata(
                    affected_package="pcre3", namespace="debian:10"
                ),
            ),
            VulnerabilityQuery(
                ["CVE-2017-18018"],
                "expected_empty_incorrect_version",
                VulnerabilityQueryMetadata(
                    affected_package="coreutils",
                    namespace="nvdv2:cves",
                    affected_package_version="10",
                ),
            ),
        ],
    )
    def test_query_vulnerabilities(self, query, expected_content):
        vulnerabilities_resp = (
            policy_engine_api.query_vulnerabilities.get_vulnerabilities(
                query.id, **asdict(query.query_metadata)
            )
        )

        assert vulnerabilities_resp == http_utils.APIResponse(200)
        expected = expected_content(query.expected_output_file)
        assert vulnerabilities_resp.body == expected
