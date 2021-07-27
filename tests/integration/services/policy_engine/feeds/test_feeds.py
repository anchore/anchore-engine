import os
import time

import pytest

from anchore_engine.common.models.schemas import (
    BatchImageVulnerabilitiesQueueMessage,
    ImageVulnerabilitiesQueueMessage,
)
from anchore_engine.db import GemMetadata, NpmMetadata, Vulnerability, session_scope
from anchore_engine.services.policy_engine.engine.feeds.download import (
    LocalFeedDataRepo,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    GrypeDBFeed,
    feed_instance_by_name,
)
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    MetadataSyncUtils,
)
from anchore_engine.subsys import logger

logger.enable_test_logging()

reason = "only packages"

empty_metadata_sync_result = ({}, [])  # No feeds synced nor requested so no errors


def test_vuln_sync(run_legacy_sync_for_feeds):
    with session_scope() as db:
        vcount = db.query(Vulnerability).count()

    logger.info("Starting with {} vuln records".format(vcount))
    assert vcount == 0, "Not starting with empty table"

    logger.info("Syncing vulnerabilities")
    t = time.time()
    run_legacy_sync_for_feeds(["vulnerabilities"])

    t = time.time() - t
    logger.info("Done with vulnerabilities. Took: {} sec".format(t))
    with session_scope() as db:
        logger.info("Has {} vuln records".format(db.query(Vulnerability).count()))


def test_package_sync(run_legacy_sync_for_feeds):
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()
    assert ncount == 0, "Not starting with empty table"
    assert gcount == 0, "Not starting with empty table"

    logger.info("Syncing packages")
    t = time.time()
    run_legacy_sync_for_feeds(["packages"])
    t = time.time() - t
    logger.info("Done with packages. Took: {} sec".format(t))
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()

    logger.info("Has {} npm records".format(ncount))
    logger.info("Has {} gem records".format(gcount))


def test_group_lookups(test_data_env):
    source_feeds = DataFeeds.get_feed_group_information(test_data_env.feed_client)
    r = MetadataSyncUtils.sync_metadata(source_feeds=source_feeds)
    assert (
        r == empty_metadata_sync_result
    ), "No metadata should be returned from sync with empty to_sync input"
    to_sync = ["vulnerabilities"]
    source_feeds = DataFeeds.get_feed_group_information(
        feed_client=test_data_env.feed_client, to_sync=to_sync
    )
    r = MetadataSyncUtils.sync_metadata(source_feeds=source_feeds, to_sync=to_sync)
    assert (
        r and len(r[0]) == 1
    ), "Metadata should be returned from sync with non-empty to_sync list"

    df = feed_instance_by_name("vulnerabilities")
    assert df is not None, "vulnerabilities feed instance not loaded"
    assert df.metadata, "No vuln metadata found"
    logger.info("Vuln feed metadata {}".format(df.metadata.to_json()))
    assert not df.group_by_name("not_a_real_Group"), "Found non-existent group"
    assert df.group_by_name("alpine:3.6"), "Should have found group alpine:3.6"


def test_sync_repo(test_data_env, test_data_path):
    feeds_repo_path = os.path.join(test_data_path, "feeds_repo")
    repo = LocalFeedDataRepo.from_disk(feeds_repo_path)
    assert repo.has_metadata(), "Repo should have metadata"
    assert repo.has_root(), "Repo should have root dir already"
    with pytest.raises(Exception):
        DataFeeds.sync_from_fetched(repo, catalog_client=None)
    source_feeds = DataFeeds.get_feed_group_information(test_data_env.feed_client)
    assert (
        MetadataSyncUtils.sync_metadata(source_feeds=source_feeds)
        == empty_metadata_sync_result
    )
    to_sync = ["vulnerabilities"]
    source_feeds = DataFeeds.get_feed_group_information(
        feed_client=test_data_env.feed_client, to_sync=to_sync
    )
    assert (
        MetadataSyncUtils.sync_metadata(source_feeds=source_feeds, to_sync=to_sync)[
            0
        ].get("vulnerabilities")
        is not None
    )
    assert DataFeeds.sync_from_fetched(repo, catalog_client=None)


def test_metadata_sync(test_data_env):
    source_feeds = DataFeeds.get_feed_group_information(test_data_env.feed_client)
    r = MetadataSyncUtils.sync_metadata(source_feeds=source_feeds)
    assert (
        r == empty_metadata_sync_result
    ), "Expected empty dict result from metadata sync with no to_sync directive"
    to_sync = ["vulnerabilities", "packages", "vulndb", "nvdv2"]
    source_feeds = DataFeeds.get_feed_group_information(
        test_data_env.feed_client, to_sync=to_sync
    )
    r = MetadataSyncUtils.sync_metadata(
        source_feeds=source_feeds,
        to_sync=to_sync,
    )
    assert r is not None, "Expected dict result from metadata sync"
    assert (
        type(r) == tuple and type(r[0]) == dict and type(r[1]) == list
    ), "Expected tuple with element 1 = dict result from metadata sync"
    assert len(r[0]) == 4, "Expected dict result from metadata sync"
    assert r[0].get("vulnerabilities")
    assert r[0].get("packages")
    assert r[0].get("vulndb")
    assert r[0].get("nvdv2")


class TestGrypeDBFeed:
    @pytest.mark.parametrize(
        "test_input, batch_size",
        [
            pytest.param([], 0, id="empty-1"),
            pytest.param([], -1, id="empty-2"),
            pytest.param([], 10, id="empty-3"),
            pytest.param(None, 0, id="none-1"),
            pytest.param(None, -1, id="none-2"),
            pytest.param(None, 10, id="none-3"),
        ],
    )
    def test_create_refresh_tasks_invalid_input(self, test_input, batch_size):
        assert GrypeDBFeed._create_refresh_tasks(test_input, batch_size) == []

    @pytest.mark.parametrize(
        "test_input, batch_size, expected",
        [
            pytest.param(
                [("x", "y", "z"), ("x", "y", "z")],
                10,
                [
                    BatchImageVulnerabilitiesQueueMessage(
                        messages=[
                            ImageVulnerabilitiesQueueMessage("x", "y", "z"),
                            ImageVulnerabilitiesQueueMessage("x", "y", "z"),
                        ]
                    )
                ],
                id="input-less-than-batch-size",
            ),
            pytest.param(
                [("x", "y", "z"), ("x", "y", "z"), ("x", "y", "z")],
                1,
                [
                    BatchImageVulnerabilitiesQueueMessage(
                        messages=[ImageVulnerabilitiesQueueMessage("x", "y", "z")]
                    ),
                    BatchImageVulnerabilitiesQueueMessage(
                        messages=[ImageVulnerabilitiesQueueMessage("x", "y", "z")]
                    ),
                    BatchImageVulnerabilitiesQueueMessage(
                        messages=[ImageVulnerabilitiesQueueMessage("x", "y", "z")]
                    ),
                ],
                id="input-greater-than-batch-size-1",
            ),
            pytest.param(
                [("x", "y", "z"), ("x", "y", "z")],
                2,
                [
                    BatchImageVulnerabilitiesQueueMessage(
                        messages=[
                            ImageVulnerabilitiesQueueMessage("x", "y", "z"),
                            ImageVulnerabilitiesQueueMessage("x", "y", "z"),
                        ]
                    ),
                ],
                id="input-equals-batch-size",
            ),
        ],
    )
    def test_create_refresh_tasks(self, test_input, batch_size, expected):
        actual = GrypeDBFeed._create_refresh_tasks(test_input, batch_size)
        assert len(actual) == len(expected)

        for actual_batch, expected_batch in zip(actual, expected):
            assert len(actual_batch.messages) == len(expected_batch.messages)
            for actual_message, expected_message in zip(
                actual_batch.messages, expected_batch.messages
            ):
                assert actual_message.account_id == expected_message.account_id
                assert actual_message.image_id == expected_message.image_id
                assert actual_message.image_digest == expected_message.image_digest
