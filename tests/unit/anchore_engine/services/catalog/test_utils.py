import pytest

from anchore_engine.common.models.policy_engine import (
    ImageVulnerabilitiesReport,
    VulnerabilityMatch,
)
from anchore_engine.services.catalog.utils import (
    VulnerabilitySummary,
    diff_identity_summary_maps,
    get_normalized_map_from_report,
    get_normalized_map_from_table,
)


@pytest.mark.parametrize(
    "test_input, expected",
    [
        pytest.param(
            [
                [
                    "GHSA-v6wp-4m6f-gcjg",
                    "Low",
                    1,
                    "aiohttp-3.7.3",
                    "3.7.4",
                    "8d4db62fbc412dd3a19f55bdf3d15bed65a7cdf9a3cf00630da685af565e2d25",
                    "None",
                    "https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    "python",
                    "vulnerabilities",
                    "github:python",
                    "aiohttp",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                    "3.7.3",
                    '{"nvd_data": [], "vendor_data": []}',
                ]
            ],
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            id="valid",
        ),
        pytest.param(
            [],
            {},
            id="empty-rows",
        ),
        pytest.param(
            None,
            {},
            id="none-rows",
        ),
    ],
)
def test_get_normalized_map_from_table(test_input, expected):
    api_response = {
        "legacy_report": {
            "multi": {
                "result": {
                    "header": [
                        "CVE_ID",
                        "Severity",
                        "*Total_Affected",
                        "Vulnerable_Package",
                        "Fix_Available",
                        "Fix_Images",
                        "Rebuild_Images",
                        "URL",
                        "Package_Type",
                        "Feed",
                        "Feed_Group",
                        "Package_Name",
                        "Package_Path",
                        "Package_Version",
                        "CVES",
                    ],
                    "rows": test_input,
                }
            }
        }
    }

    assert get_normalized_map_from_table(api_response) == expected


@pytest.mark.parametrize(
    "test_input, error",
    [
        pytest.param(
            {
                "legacy_report": {
                    "multi": {
                        "result": {
                            "header": [
                                "*Total_Affected",
                                "Vulnerable_Package",
                                "Fix_Images",
                                "Rebuild_Images",
                                "URL",
                                "CVES",
                            ],
                            "rows": [
                                [
                                    "1",
                                    "2",
                                    3,
                                    "4",
                                    "5",
                                    "6",
                                    "7",
                                    "8",
                                    "9",
                                    "10",
                                    "11",
                                    "12",
                                    "13",
                                    "14",
                                    "15",
                                ]
                            ],
                        }
                    }
                }
            },
            ValueError,
            id="invalid-header",
        ),
        pytest.param(
            {
                "legacy_report": {
                    "multi": {
                        "result": {
                            "header": [
                                "CVE_ID",
                                "Severity",
                                "*Total_Affected",
                                "Vulnerable_Package",
                                "Fix_Available",
                                "Fix_Images",
                                "Rebuild_Images",
                                "URL",
                                "Package_Type",
                                "Feed",
                                "Feed_Group",
                                "Package_Name",
                                "Package_Path",
                                "Package_Version",
                                "CVES",
                            ],
                            "rows": [
                                [
                                    "GHSA-v6wp-4m6f-gcjg",
                                    "Low",
                                    1,
                                ]
                            ],
                        }
                    }
                }
            },
            IndexError,
            id="invalid-row",
        ),
        pytest.param(
            {
                "result": {
                    "header": [
                        "CVE_ID",
                        "Severity",
                        "*Total_Affected",
                        "Vulnerable_Package",
                        "Fix_Available",
                    ],
                    "rows": [
                        [
                            "GHSA-v6wp-4m6f-gcjg",
                            "Low",
                            1,
                        ]
                    ],
                }
            },
            KeyError,
            id="invalid-response-format",
        ),
    ],
)
def test_get_normalized_map_from_table_exceptions(test_input, error):
    with pytest.raises(error):
        assert get_normalized_map_from_table(test_input) == {}


@pytest.mark.parametrize(
    "test_input, expected",
    [
        pytest.param(
            [
                VulnerabilityMatch.from_json(
                    {
                        "artifact": {
                            "cpe": None,
                            "cpes": [],
                            "location": "/usr/lib/python3.8/site-packages/aiohttp",
                            "name": "aiohttp",
                            "pkg_type": "python",
                            "version": "3.7.3",
                        },
                        "fix": {
                            "advisories": [],
                            "observed_at": "2021-03-31T17:30:49Z",
                            "versions": ["3.7.4"],
                            "wont_fix": False,
                        },
                        "match": {"detected_at": "2021-06-07T20:20:47Z"},
                        "nvd": [],
                        "vulnerability": {
                            "cvss": [],
                            "description": None,
                            "feed": "vulnerabilities",
                            "feed_group": "github:python",
                            "link": "https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                            "severity": "Low",
                            "vulnerability_id": "GHSA-v6wp-4m6f-gcjg",
                        },
                    }
                )
            ],
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            id="valid",
        ),
        pytest.param(
            [],
            {},
            id="empty-results",
        ),
        pytest.param(
            None,
            {},
            id="none-results",
        ),
    ],
)
def test_get_normalized_map_from_report(test_input, expected):
    report = ImageVulnerabilitiesReport(results=test_input)
    assert get_normalized_map_from_report(report) == expected


@pytest.mark.parametrize(
    "old_input, new_input, diff",
    [
        pytest.param(
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {
                "added": [],
                "removed": [],
                "updated": [],
            },
            id="same",
        ),
        pytest.param(
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {},
            {
                "added": [],
                "removed": [
                    VulnerabilitySummary(
                        CVE_ID="GHSA-v6wp-4m6f-gcjg",
                        Severity="Low",
                        Vulnerable_Package="aiohttp-3.7.3",
                        Fix_Available="3.7.4",
                        URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                        Package_Name="aiohttp",
                        Package_Version="3.7.3",
                        Package_Type="python",
                        Feed="vulnerabilities",
                        Feed_Group="github:python",
                    ).__dict__
                ],
                "updated": [],
            },
            id="removed",
        ),
        pytest.param(
            {},
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {
                "added": [
                    VulnerabilitySummary(
                        CVE_ID="GHSA-v6wp-4m6f-gcjg",
                        Severity="Low",
                        Vulnerable_Package="aiohttp-3.7.3",
                        Fix_Available="3.7.4",
                        URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                        Package_Name="aiohttp",
                        Package_Version="3.7.3",
                        Package_Type="python",
                        Feed="vulnerabilities",
                        Feed_Group="github:python",
                    ).__dict__
                ],
                "removed": [],
                "updated": [],
            },
            id="added",
        ),
        pytest.param(
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="Low",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {
                (
                    "GHSA-v6wp-4m6f-gcjg",
                    "github:python",
                    "aiohttp",
                    "3.7.3",
                    "python",
                    "/usr/lib/python3.8/site-packages/aiohttp",
                ): VulnerabilitySummary(
                    CVE_ID="GHSA-v6wp-4m6f-gcjg",
                    Severity="High",
                    Vulnerable_Package="aiohttp-3.7.3",
                    Fix_Available="3.7.4",
                    URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                    Package_Name="aiohttp",
                    Package_Version="3.7.3",
                    Package_Type="python",
                    Feed="vulnerabilities",
                    Feed_Group="github:python",
                )
            },
            {
                "added": [],
                "removed": [],
                "updated": [
                    VulnerabilitySummary(
                        CVE_ID="GHSA-v6wp-4m6f-gcjg",
                        Severity="High",
                        Vulnerable_Package="aiohttp-3.7.3",
                        Fix_Available="3.7.4",
                        URL="https://github.com/advisories/GHSA-v6wp-4m6f-gcjg",
                        Package_Name="aiohttp",
                        Package_Version="3.7.3",
                        Package_Type="python",
                        Feed="vulnerabilities",
                        Feed_Group="github:python",
                    ).__dict__
                ],
            },
            id="updated",
        ),
        pytest.param({}, {}, {"added": [], "removed": [], "updated": []}, id="empty"),
        pytest.param(
            None, None, {"added": [], "removed": [], "updated": []}, id="none"
        ),
    ],
)
def test_diff_identity_summary_maps(old_input, new_input, diff):
    assert diff_identity_summary_maps(old_input, new_input) == diff
