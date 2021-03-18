import os

import pytest

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from tests.functional.services.policy_engine.conftest import read_expected_content
from tests.functional.services.policy_engine.feeds_data_tests.conftest import (
    FEEDS_DATA_PATH_PREFIX,
)
from tests.functional.services.utils import http_utils


def idfn(val):
    return val["name"]


def build_feed_sync_test_matrix():
    """
    Builds the parameters to use for the feed sync test by reading files of expected content
    Creates an array of tuples:
        1. first index is the feed object from the feeds index.json file
        2. second index is the group object from the individual feed's index file
    """
    params = []
    feeds = read_expected_content(
        __file__, os.path.join(FEEDS_DATA_PATH_PREFIX, "index")
    )["feeds"]
    for feed in feeds:
        groups = read_expected_content(
            __file__, os.path.join(FEEDS_DATA_PATH_PREFIX, feed["name"], "index")
        )["groups"]
        for group in groups:
            params.append((feed, group))

    return params


class TestFeedSync:
    @classmethod
    def _find_by_attr(cls, attr, records, value):
        """
        From a list of objects/dictionaries, selects first index with matching value of specified attr.
        Returns None if nothing is found
        :param records: list of objects or dictionaries that are expected to have attr
        :type records: list
        :return: dict with matching value for specified attr or 'None' if nothing found
        :rtype: Union[dict, None]
        """
        for record in records:
            if record[attr] == value:
                return record
        return None

    @classmethod
    def _get_vuln_ids(cls, expected_vulns):
        """
        From a list of expected vulns taken from feeds service, find corresponding vulnerability ids for querying anchore
        :param expected_vulns: list of records in group from feed
        :type expected_vulns: list
        :return: list of vulnerabilitiy_ids as they would be stored in anchore
        :rtype: list
        """
        vuln_ids = []
        for vuln in expected_vulns:
            # GHSA
            if "Advisory" in vuln:
                vuln_ids.append(vuln["Advisory"]["ghsaId"])
            # NVDV2
            if "cve" in vuln:
                vuln_ids.append(vuln["cve"]["CVE_data_meta"]["ID"])
            # Vulnerabilities
            if "Vulnerability" in vuln:
                # GHSA also has "Vulnerabilities", but value is empty object
                if "Name" in vuln["Vulnerability"]:
                    vuln_ids.append(vuln["Vulnerability"]["Name"])
        return vuln_ids

    @pytest.fixture(scope="class")
    def sync_feeds(self):
        """
        Uses clear database fixture and calls a feed sync. Scoped to occur only once for the class rather than each test
        """
        return policy_engine_api.feeds.feeds_sync()

    def test_feeds_sync_schema(self, sync_feeds, schema_validator):
        feed_sync_resp = sync_feeds
        feeds_sync_schema_validator = schema_validator("feeds_sync.schema.json")
        is_valid: bool = feeds_sync_schema_validator.is_valid(feed_sync_resp.body)
        assert is_valid, "\n".join(
            [
                str(e)
                for e in feeds_sync_schema_validator.iter_errors(feed_sync_resp.body)
            ]
        )

    def test_feeds_get_schema(self, sync_feeds, schema_validator):
        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        validator = schema_validator("feeds_get.schema.json")
        is_valid: bool = validator.is_valid(feeds_get_resp.body)
        assert is_valid, "\n".join(
            [str(e) for e in validator.iter_errors(feeds_get_resp.body)]
        )

    @pytest.mark.parametrize(
        "expected_feed, expected_group", build_feed_sync_test_matrix(), ids=idfn
    )
    def test_expected_feed_sync(
        self, expected_feed, expected_group, expected_content, sync_feeds
    ):
        # sync feeds and verify that the feed was a success
        feed_sync_resp = sync_feeds
        assert feed_sync_resp == http_utils.APIResponse(200)
        assert (
            self._find_by_attr("feed", feed_sync_resp.body, expected_feed["name"])[
                "status"
            ]
            == "success"
        )

        # call get all feeds
        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)

        # assert that expected feed is present in found list and enabled
        actual_feed = self._find_by_attr(
            "name", feeds_get_resp.body, expected_feed["name"]
        )
        assert not isinstance(actual_feed, type(None))
        assert actual_feed["enabled"]

        # Verify that the expected group is present and enabled
        actual_group = self._find_by_attr(
            "name", actual_feed["groups"], expected_group["name"]
        )
        assert not isinstance(actual_group, type(None))
        assert actual_group["enabled"]

        # get expected cves and query to verify the count in the get feeds response
        expected_vulns = expected_content(
            os.path.join(
                FEEDS_DATA_PATH_PREFIX,
                expected_feed["name"],
                expected_group["name"],
            )
        )["data"]
        assert actual_group["record_count"] == len(expected_vulns)

        # using expected cves, query the vulnerabilites endpoint to verify they are in the system
        vuln_ids = self._get_vuln_ids(expected_vulns)
        vuln_response = policy_engine_api.query_vulnerabilities.get_vulnerabilities(
            vuln_ids, namespace=expected_group["name"]
        )
        assert len(vuln_response.body) == len(expected_vulns)
        assert len(set([x["id"] for x in vuln_response.body])) == len(expected_vulns)
