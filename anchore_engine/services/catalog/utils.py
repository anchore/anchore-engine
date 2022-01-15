from dataclasses import dataclass
from operator import itemgetter
from typing import Dict, Tuple

from marshmallow.exceptions import ValidationError

from anchore_engine.common.models.policy_engine import (
    ImageVulnerabilitiesReport,
    VulnerabilityMatch,
)
from anchore_engine.subsys import logger


@dataclass(eq=True, frozen=True)  # for comparison ops
class VulnerabilitySummary:
    """
    Backwards compatible condensed representation of vulnerability used for handling vulnerability notifications

    Copied from summary_elements of anchore_engine/utils.py
    """

    CVE_ID: str
    Severity: str
    Vulnerable_Package: str
    Fix_Available: str
    URL: str
    Package_Name: str
    Package_Version: str
    Package_Type: str
    Feed: str
    Feed_Group: str

    @staticmethod
    def from_match(match: VulnerabilityMatch):
        return VulnerabilitySummary(
            CVE_ID=match.vulnerability.vulnerability_id,
            Severity=match.vulnerability.severity,
            Vulnerable_Package="{}-{}".format(
                match.artifact.name, match.artifact.version
            ),
            Fix_Available=",".join(match.fix.versions)
            if match.fix.versions
            else "None",
            URL=match.vulnerability.link,
            Package_Name=match.artifact.name,
            Package_Version=match.artifact.version,
            Package_Type=match.artifact.pkg_type,
            Feed=match.vulnerability.feed,
            Feed_Group=match.vulnerability.feed_group,
        )

    @staticmethod
    def from_tuple(summary_tuple: Tuple):
        return VulnerabilitySummary(*summary_tuple)


def diff_image_vulnerabilities(old_result=None, new_result=None):
    """
    Returns the diff of two cve results. Only compares two valid results, if either is None or empty, will return empty.

    :param cve_record:
    :return: dict with diff results: {'added': [], 'updated': [], 'removed': []}
    """

    if not old_result or not new_result:
        return {}  # Nothing to do

    old_vuln_map = get_normalized_identity_summary_map(old_result)
    new_vuln_map = get_normalized_identity_summary_map(new_result)

    return diff_identity_summary_maps(old_vuln_map, new_vuln_map)


def get_normalized_identity_summary_map(api_response):
    """
    Given an API response for image vulnerabilities - legacy table or new format, returns a dictionary with key value
    pairs that represent the vulnerability identity and summary respectively.

    An identity-summary key-value pair is necessary since the diffs have to compute added, removed and updated items.
    Identity is used for computing items that were added or removed, summary is used for computing the updates
    """
    try:
        # try parsing the report into new format
        report = ImageVulnerabilitiesReport.from_json(api_response)
        return get_normalized_map_from_report(report)
    except ValidationError:
        logger.warn(
            "Unable to parse api response as a report object, falling back to legacy table format"
        )
        # fall back to old table format
        return get_normalized_map_from_table(api_response)


def get_normalized_map_from_report(
    report: ImageVulnerabilitiesReport,
) -> Dict[Tuple, VulnerabilitySummary]:
    """
    Transforms the input into a dictionary. Each match object in the report is transformed into a key value pair
    where the key is an identity tuple and value is an instance of VulnerabilitySummary

    Example of a match instance transformed into key value pair
    (
        'GHSA-v6wp-4m6f-gcjg',
        'github:python',
        'aiohttp',
        '3.7.3',
        '/usr/lib/python3.8/site-packages/aiohttp'
    ): VulnerabilitySummary(
            CVE_ID='GHSA-v6wp-4m6f-gcjg',
            Severity='Low',
            Vulnerable_Package='aiohttp-3.7.3',
            Fix_Available='3.7.4',
            URL='https://github.com/advisories/GHSA-v6wp-4m6f-gcjg',
            Package_Name='aiohttp',
            Package_Version='3.7.3',
            Package_Type='python',
            Feed='vulnerabilities',
            Feed_Group='github:python'
        )
    }

    """

    if not report or not report.results:
        return {}

    return {
        match.identity_tuple(): VulnerabilitySummary.from_match(match)
        for match in report.results
    }


def get_normalized_map_from_table(table) -> Dict[Tuple, VulnerabilitySummary]:
    """
    Transforms the legacy image vulnerabilities response into a dictionary. Each row of results is transformed into a key-value pair where in
    key is an identity tuple and value is an instance of VulnerabilitySummary

    For instance, the following row result in legacy report

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
        "{\"nvd_data\": [], \"vendor_data\": []}"
    ]

    is transformed to the below key-value pair

    (
        'GHSA-v6wp-4m6f-gcjg',
        'github:python',
        'aiohttp',
        '3.7.3',
        '/usr/lib/python3.8/site-packages/aiohttp'
    ): VulnerabilitySummary(
        CVE_ID='GHSA-v6wp-4m6f-gcjg',
        Severity='Low',
        Vulnerable_Package='aiohttp-3.7.3',
        Fix_Available='3.7.4',
        URL='https://github.com/advisories/GHSA-v6wp-4m6f-gcjg',
        Package_Name='aiohttp',
        Package_Version='3.7.3',
        Package_Type='python',
        Feed='vulnerabilities',
        Feed_Group='github:python'
        )
    }

    Partially lifted from anchore_engine/utils.py. Can be deprecated and removed after legacy format is no longer widely used

    """

    table_header = table["legacy_report"]["multi"]["result"]["header"]
    table_rows = table["legacy_report"]["multi"]["result"]["rows"]

    if not table_header or not table_rows:
        return {}

    # header is a list
    # [
    #     "CVE_ID",
    #     "Severity",
    #     "*Total_Affected",
    #     "Vulnerable_Package",
    #     "Fix_Available",
    #     "Fix_Images",
    #     "Rebuild_Images",
    #     "URL",
    #     "Package_Type",
    #     "Feed",
    #     "Feed_Group",
    #     "Package_Name",
    #     "Package_Path",
    #     "Package_Version",
    #     "CVES",
    # ]

    # this mimics the VulnerabilityMatch.identity_tuple(),
    # not bothering with a dataclass since 1. tuples are slightly faster 2. this function will be deprecated in the near future after the switch to new format is complete
    identity_elements = [
        "CVE_ID",
        "Feed_Group",
        "Package_Name",
        "Package_Version",
        "Package_Type",
        "Package_Path",
    ]

    summary_elements = [
        "CVE_ID",
        "Severity",
        "Vulnerable_Package",
        "Fix_Available",
        "URL",
        "Package_Name",
        "Package_Version",
        "Package_Type",
        "Feed",
        "Feed_Group",
    ]

    identiy_indices = [table_header.index(item) for item in identity_elements]
    summary_indices = [table_header.index(item) for item in summary_elements]

    return {
        itemgetter(*identiy_indices)(row): VulnerabilitySummary.from_tuple(
            itemgetter(*summary_indices)(row)
        )
        for row in table_rows
    }


def diff_identity_summary_maps(
    old_vuln_map: Dict[Tuple, VulnerabilitySummary] = None,
    new_vuln_map: Dict[Tuple, VulnerabilitySummary] = None,
):
    """
    Given previous vuln-scan map and new vuln-scan map for the same image, return a diff as a dictionary

    Keys:
    {
        'added': [],
        'removed': [],
        'updated': []
    }

    Borrowed from anchore_engine/utils.py item_diffs()
    """

    if not old_vuln_map:
        old_vuln_map = {}

    if not new_vuln_map:
        new_vuln_map = {}

    old_identities = set(old_vuln_map.keys())
    new_identities = set(new_vuln_map.keys())

    added = [
        new_vuln_map[x].__dict__ for x in new_identities.difference(old_identities)
    ]
    removed = [
        old_vuln_map[x].__dict__ for x in old_identities.difference(new_identities)
    ]

    updated = [
        new_vuln_map[x].__dict__
        for x in new_identities.intersection(old_identities)
        if new_vuln_map[x] != old_vuln_map[x]
    ]

    return {"added": added, "removed": removed, "updated": updated}
