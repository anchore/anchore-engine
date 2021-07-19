import pytest

from anchore_engine.common.models.policy_engine import (
    FixedArtifact,
    VulnerabilityMatch,
    Vulnerability,
    Artifact,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import GrypeProvider


class TestGrypeProvider:
    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix="true"))],
                id="str",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix="  "))],
                id="whitespace",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=""))],
                id="blank",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=False))],
                id="boolean_false",
            ),
            pytest.param(
                [VulnerabilityMatch(fix=None)],
                id="fix_none",
            ),
        ],
    )
    def test_exclude_wont_fix_false(self, test_input):
        assert len(GrypeProvider._exclude_wont_fix(test_input)) == 1

    @pytest.mark.parametrize(
        "test_input",
        [
            pytest.param(
                [VulnerabilityMatch(fix=FixedArtifact(wont_fix=True))],
                id="boolean_true",
            ),
        ],
    )
    def test_exclude_wont_fix_true(self, test_input):
        assert len(GrypeProvider._exclude_wont_fix(test_input)) == 0

    @pytest.mark.parametrize(
        "test_input, expected_output",
        [
            pytest.param(
                Vulnerability(vulnerability_id="CVE-xyz"),
                [
                    {
                        "name": "foo",
                        "version": "0.0",
                        "type": "bar",
                        "namespace": None,
                        "severity": None,
                    }
                ],
                id="match-1",
            ),
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-xyz", severity="Critical", feed_group="meh"
                ),
                [
                    {
                        "name": "foo",
                        "version": "0.0",
                        "type": "bar",
                        "namespace": "meh",
                        "severity": "Critical",
                    }
                ],
                id="match-2",
            ),
            pytest.param(
                Vulnerability(
                    vulnerability_id="CVE-pqr", severity="Critical", feed_group="meh"
                ),
                [],
                id="no-match",
            ),
        ],
    )
    def test_filter_vulnerability_matches_no_optional_filters(
        self, test_input, expected_output
    ):
        vuln_match = VulnerabilityMatch(
            vulnerability=test_input,
            artifact=Artifact(
                name="foo",
                version="0.0",
                pkg_type="bar",
                location="/usr/local/lib",
            ),
        )

        results = GrypeProvider._filter_vulnerability_matches(
            matches=[vuln_match],
            vulnerability_id="CVE-xyz",
            severity_filter=None,
            namespace_filter=None,
            affected_package_filter=None,
            vendor_only=None,
        )

        assert results == expected_output

    @pytest.mark.parametrize(
        "test_input, test_filter, expected_output",
        [
            pytest.param(
                True,
                False,
                [
                    {
                        "name": "foo",
                        "version": None,
                        "type": None,
                        "namespace": None,
                        "severity": None,
                    }
                ],
                id="wontfix-true_vendoronly_false",
            ),
            pytest.param(
                False,
                False,
                [
                    {
                        "name": "foo",
                        "version": None,
                        "type": None,
                        "namespace": None,
                        "severity": None,
                    }
                ],
                id="wontfix-false_vendoronly_false",
            ),
            pytest.param(
                False,
                True,
                [
                    {
                        "name": "foo",
                        "version": None,
                        "type": None,
                        "namespace": None,
                        "severity": None,
                    }
                ],
                id="wontfix-false_vendoronly_true",
            ),
            pytest.param(
                True,
                True,
                [],
                id="wontfix-true_vendoronly_true",
            ),
        ],
    )
    def test_filter_vulnerability_matches_vendor_only(
        self, test_input, test_filter, expected_output
    ):
        vuln_match = VulnerabilityMatch(
            vulnerability=Vulnerability(vulnerability_id="CVE-xyz"),
            artifact=Artifact(name="foo"),
            fix=FixedArtifact(wont_fix=test_input),
        )

        results = GrypeProvider._filter_vulnerability_matches(
            matches=[vuln_match],
            vulnerability_id="CVE-xyz",
            severity_filter=None,
            namespace_filter=None,
            affected_package_filter=None,
            vendor_only=test_filter,
        )

        assert results == expected_output

    @pytest.mark.parametrize(
        "test_input, test_filter, expected_output",
        [
            pytest.param(
                "High",
                "Critical",
                [],
                id="no-match",
            ),
            pytest.param(
                "High",
                "High",
                [
                    {
                        "name": "foo",
                        "version": None,
                        "type": None,
                        "namespace": None,
                        "severity": "High",
                    }
                ],
                id="match",
            ),
        ],
    )
    def test_filter_vulnerability_matches_severity(
        self, test_input, test_filter, expected_output
    ):
        vuln_match = VulnerabilityMatch(
            vulnerability=Vulnerability(
                vulnerability_id="CVE-xyz", severity=test_input
            ),
            artifact=Artifact(name="foo"),
        )

        results = GrypeProvider._filter_vulnerability_matches(
            matches=[vuln_match],
            vulnerability_id="CVE-xyz",
            severity_filter=test_filter,
            namespace_filter=None,
            affected_package_filter=None,
            vendor_only=None,
        )

        assert results == expected_output

    @pytest.mark.parametrize(
        "test_input, test_filter, expected_output",
        [
            pytest.param(
                "foo",
                "bar",
                [],
                id="no-match",
            ),
            pytest.param(
                "meh",
                "meh",
                [
                    {
                        "name": "foo",
                        "version": None,
                        "type": None,
                        "namespace": "meh",
                        "severity": None,
                    }
                ],
                id="match",
            ),
        ],
    )
    def test_filter_vulnerability_matches_namespace(
        self, test_input, test_filter, expected_output
    ):
        vuln_match = VulnerabilityMatch(
            vulnerability=Vulnerability(
                vulnerability_id="CVE-xyz", feed_group=test_input
            ),
            artifact=Artifact(name="foo"),
        )

        results = GrypeProvider._filter_vulnerability_matches(
            matches=[vuln_match],
            vulnerability_id="CVE-xyz",
            severity_filter=None,
            namespace_filter=test_filter,
            affected_package_filter=None,
            vendor_only=None,
        )

        assert results == expected_output
