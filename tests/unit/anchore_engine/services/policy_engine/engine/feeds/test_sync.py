import datetime

import pytest

from anchore_engine.db.entities.policy_engine import FeedMetadata
from anchore_engine.services.policy_engine import init_feed_registry
from anchore_engine.services.policy_engine.engine.feeds.feeds import feed_registry
from anchore_engine.services.policy_engine.engine.feeds.sync import (
    NvdV2Feed,
    PackagesFeed,
    VulnerabilityFeed,
)
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    MetadataSyncUtils,
)


@pytest.fixture
def feed_db_records():
    init_feed_registry()
    recs = {}
    for r in feed_registry.registered_feed_names():
        recs[r] = FeedMetadata()
        recs[r].name = r
        recs[r].last_update = datetime.datetime.utcnow()
        recs[r].created_at = datetime.datetime.utcnow()
        recs[r].last_full_sync = None
        recs[r].description = "description test"
        recs[r].access_tier = 0
        recs[r].groups = []

    return recs


def test_pivot_and_filter_feeds_by_config(feed_db_records):
    v = [VulnerabilityFeed.__feed_name__]
    v_db = [feed_db_records[VulnerabilityFeed.__feed_name__]]

    v_n = [VulnerabilityFeed.__feed_name__, NvdV2Feed.__feed_name__]
    v_n_db = [
        feed_db_records[VulnerabilityFeed.__feed_name__],
        feed_db_records[NvdV2Feed.__feed_name__],
    ]

    n = [NvdV2Feed.__feed_name__]
    n_db = [feed_db_records[NvdV2Feed.__feed_name__]]

    p = [PackagesFeed.__feed_name__]
    p_db = [feed_db_records[PackagesFeed.__feed_name__]]

    matrix = [
        {"to_sync": [], "source_found": [], "db_found": [], "expected_result": {}},
        {
            "to_sync": v,
            "source_found": v,
            "db_found": v_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ]
            },
        },
        {
            "to_sync": v,
            "source_found": v,
            "db_found": v_n_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ]
            },
        },
        {
            "to_sync": v,
            "source_found": v_n,
            "db_found": v_n_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ]
            },
        },
        {
            "to_sync": v_n,
            "source_found": v_n,
            "db_found": v_n_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ],
                NvdV2Feed.__feed_name__: feed_db_records[NvdV2Feed.__feed_name__],
            },
        },
        {"to_sync": n, "source_found": v, "db_found": v_db, "expected_result": {}},
        {"to_sync": v, "source_found": n, "db_found": v_db, "expected_result": {}},
        {"to_sync": v, "source_found": n, "db_found": p_db, "expected_result": {}},
        {
            "to_sync": v_n,
            "source_found": v_n,
            "db_found": v_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ]
            },
        },
        {
            "to_sync": v_n,
            "source_found": v,
            "db_found": v_n_db,
            "expected_result": {
                VulnerabilityFeed.__feed_name__: feed_db_records[
                    VulnerabilityFeed.__feed_name__
                ]
            },
        },
    ]

    for input in matrix:
        assert (
            MetadataSyncUtils._pivot_and_filter_feeds_by_config(
                input["to_sync"], input["source_found"], input["db_found"]
            )
            == input["expected_result"]
        )
