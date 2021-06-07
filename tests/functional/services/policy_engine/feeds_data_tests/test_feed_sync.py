import os

import pytest

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from anchore_engine.services.policy_engine.engine.feeds.feeds import GrypeDBFeed
from tests.functional.services.policy_engine.conftest import (
    is_legacy_provider,
    read_expected_content,
)
from tests.functional.services.policy_engine.feeds_data_tests.conftest import (
    FEEDS_DATA_PATH_PREFIX,
)
from tests.functional.services.utils import http_utils


def idfn(val):
    """
    Function to assign meaningful ids to tests that work with list of expected groups and feeds
    """
    return val


def build_feed_sync_test_matrix():
    """
    Builds the parameters to use for the feed sync test by reading files of expected content
    Creates an array of tuples:
        1. first index is the feed object from the feeds index.json file
        2. second index is the group object from the individual feed's index file
        3. Third index is expected count of vulns for that group

    Handles grype vs legacy for expected content
    """
    params = []

    # if legacy provider, build expected feed list from mocked data
    if is_legacy_provider():
        feeds = read_expected_content(
            __file__, os.path.join(FEEDS_DATA_PATH_PREFIX, "index")
        )["feeds"]
        for feed in feeds:
            groups = read_expected_content(
                __file__, os.path.join(FEEDS_DATA_PATH_PREFIX, feed["name"], "index")
            )["groups"]
            for group in groups:
                params.append((feed["name"], group["name"], 10))
    else:
        feed = GrypeDBFeed.__feed_name__
        expected_groups = read_expected_content(
            __file__, "expected_grype_feed_and_group_counts"
        )

        for group, count in expected_groups.items():
            params.append((feed, group, int(count)))

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
    def initial_feed_sync_resp(self):
        """
        Uses clear database fixture and calls a feed sync witha  force flush.
        Scoped to occur only once for the class rather than each test
        """
        return policy_engine_api.feeds.feeds_sync(force_flush=True)

    def test_feeds_sync_schema(self, initial_feed_sync_resp, schema_validator):
        """
        Verifies that the return object from the endpoint to trigger a feed sync matches expected schema
        """
        feeds_sync_schema_validator = schema_validator("feeds_sync.schema.json")
        is_valid: bool = feeds_sync_schema_validator.is_valid(
            initial_feed_sync_resp.body
        )
        assert is_valid, "\n".join(
            [
                str(e)
                for e in feeds_sync_schema_validator.iter_errors(
                    initial_feed_sync_resp.body
                )
            ]
        )

    def test_feeds_get_schema(self, initial_feed_sync_resp, schema_validator):
        """
        Verifies that the return object from the endpoint to list feeds matches expected schema
        """
        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        validator = schema_validator("feeds_get.schema.json")
        is_valid: bool = validator.is_valid(feeds_get_resp.body)
        assert is_valid, "\n".join(
            [str(e) for e in validator.iter_errors(feeds_get_resp.body)]
        )

    @pytest.mark.parametrize(
        "expected_feed, expected_group, expected_count",
        build_feed_sync_test_matrix(),
        ids=idfn,
    )
    def test_expected_feed_sync_post(
        self,
        expected_feed,
        expected_group,
        expected_count,
        expected_content,
        initial_feed_sync_resp,
        is_legacy_test,
    ):
        """
        Tests that the post endpoint to trigger a feed sync returns expected content
        Does this using parameterized list of expected feeds, groups, and the expected counts of that group
        In addition to asserting the feed, gorup, and count is accurate, it also verifies each were a "success"
        Uses the initial sync fixture for the resp
        """
        assert initial_feed_sync_resp == http_utils.APIResponse(200)
        actual_feed = self._find_by_attr(
            "feed", initial_feed_sync_resp.body, expected_feed
        )
        assert actual_feed is not None
        assert actual_feed["status"] == "success"

        actual_group = self._find_by_attr(
            "group", actual_feed["groups"], expected_group
        )
        assert not isinstance(actual_group, type(None))
        assert actual_group["status"] == "success"
        assert actual_group["updated_record_count"] == expected_count
        assert actual_group["total_time_seconds"] > 0

    @pytest.mark.parametrize(
        "expected_feed, expected_group, expected_count",
        build_feed_sync_test_matrix(),
        ids=idfn,
    )
    def test_expected_feed_sync_get_feeds(
        self,
        expected_feed,
        expected_group,
        expected_count,
        expected_content,
        initial_feed_sync_resp,
        is_legacy_test,
    ):
        """
        Tests that the list feeds endpoint returns expected content after a feed sync has been completed
        Does this using parameterized list of expected feeds, groups, and the expected counts of that group
        """
        # sync feeds and verify that the feed was a success
        initial_feed_sync_resp = initial_feed_sync_resp
        assert initial_feed_sync_resp == http_utils.APIResponse(200)

        # call get all feeds
        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)

        # assert that expected feed is present in found list and enabled
        actual_feed = self._find_by_attr("name", feeds_get_resp.body, expected_feed)
        assert not isinstance(actual_feed, type(None))
        assert actual_feed["enabled"] is True

        # Verify that the expected group is present and enabled
        actual_group = self._find_by_attr("name", actual_feed["groups"], expected_group)
        assert not isinstance(actual_group, type(None))
        assert actual_group["enabled"]
        assert actual_group["record_count"] == expected_count

    def test_sync_timestamps_updated(self, initial_feed_sync_resp):
        """
        Verifies that when a feed sync is triggered, the last sync and last updated timestamps are all updated
        Should not sync any new data that is not already present from initial feed sync so this testing the case in
        which nothing changes other than the time stamps
        """
        first_feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        assert first_feeds_get_resp == http_utils.APIResponse(200)

        # From the first sync, build a has where key is feed name and value contains timestamps of feed and groups
        first_feed_sync = {}
        for feed in first_feeds_get_resp.body:
            group_timestamps = {}
            for group in feed["groups"]:
                group_timestamps[group["name"]] = group["last_sync"]

            first_feed_sync[feed["name"]] = {
                "last_full_sync": feed["last_full_sync"],
                "group_timestamps": group_timestamps,
            }

        # Sync again and call the get endpoint
        second_feeds_post_resp = policy_engine_api.feeds.feeds_sync()
        assert second_feeds_post_resp == http_utils.APIResponse(200)
        second_feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        assert second_feeds_get_resp == http_utils.APIResponse(200)

        # verify length of feeds is the same between first and second sync
        assert len(second_feeds_get_resp.body) == len(first_feeds_get_resp.body)

        # loop over second feed sync and verify the timestamps are all greater than the first
        for second_feed in second_feeds_get_resp.body:
            first_feed = first_feed_sync[second_feed["name"]]
            assert first_feed is not None

            assert first_feed["last_full_sync"] < second_feed["last_full_sync"]
            for second_group in second_feed["groups"]:
                assert (
                    first_feed["group_timestamps"][second_group["name"]]
                    < second_group["last_sync"]
                )

    ############# Grype specific tests #################
    @pytest.mark.skipif(is_legacy_provider(), reason="skipping grype specific test")
    def test_updated_record_count_on_resync(self, initial_feed_sync_resp):
        """
        Tests that the updated record count on resync when data not flushed is 0
        This is a grype specific sync becuase this does not appear to be the behavior for legacy prvoider
        """
        resync_resp = policy_engine_api.feeds.feeds_sync()
        for feed in resync_resp.body:
            for group in feed["groups"]:
                assert group["updated_record_count"] == 0

    ########### Legacy specific tests ################
    @pytest.mark.skipif(
        not is_legacy_provider(), reason="skipping legacy specific test"
    )
    def test_no_grypedb_feed_if_legacy(self, initial_feed_sync_resp):
        """
        If is legacy test, verify that grypedb feed is not returned when getting list feeds
        """
        assert initial_feed_sync_resp == http_utils.APIResponse(200)
        grypedb_feed = self._find_by_attr(
            "feed", initial_feed_sync_resp.body, GrypeDBFeed.__feed_name__
        )
        assert grypedb_feed is None

        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        grypedb_feed = self._find_by_attr(
            "name", feeds_get_resp.body, GrypeDBFeed.__feed_name__
        )
        assert grypedb_feed is None

    @pytest.mark.skipif(
        not is_legacy_provider(), reason="skipping legacy specific test"
    )
    @pytest.mark.parametrize(
        "expected_feed, expected_group, expected_count",
        build_feed_sync_test_matrix(),
        ids=idfn,
    )
    def test_verify_vulns_present(
        self,
        initial_feed_sync_resp,
        expected_content,
        expected_feed,
        expected_group,
        expected_count,
    ):
        """
        Verifies that the vulnerabilites are present by querying the vulnerabilities endpoint
        Currently skips if not using grype provider
        This could be done for grype, but it uses a full db and need to check a much larger number of vulns
        """
        # get expected cves and query to verify the count in the get feeds response
        expected_vulns = expected_content(
            os.path.join(
                FEEDS_DATA_PATH_PREFIX,
                expected_feed,
                expected_group,
            )
        )["data"]

        # using expected cves, query the vulnerabilities endpoint to verify they are in the system
        vuln_ids = self._get_vuln_ids(expected_vulns)
        vuln_response = policy_engine_api.query_vulnerabilities.get_vulnerabilities(
            vuln_ids, namespace=expected_group
        )
        assert len(vuln_response.body) == len(expected_vulns)
        assert len(set([x["id"] for x in vuln_response.body])) == len(expected_vulns)
