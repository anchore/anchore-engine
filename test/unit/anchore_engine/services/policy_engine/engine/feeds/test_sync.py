import pytest
import datetime
from anchore_engine.services.policy_engine.engine.feeds.sync import get_selected_feeds_to_sync, get_feeds_config, DataFeeds, DataFeed, FeedMetadata, VulnDBFeed, VulnerabilityFeed, NvdV2Feed, PackagesFeed


@pytest.fixture
def feed_db_records():
    recs = {}
    for r in DataFeed.registered_feed_names():
        recs[r] = FeedMetadata()
        recs[r].name = r
        recs[r].last_update = datetime.datetime.utcnow()
        recs[r].created_at = datetime.datetime.utcnow()
        recs[r].last_full_sync = None
        recs[r].description = "description test"
        recs[r].access_tier = 0
        recs[r].groups = []

    return recs


def test_get_feeds_config():
    matrix = [
        ({}, {}),
        ({'something': {'feeds': {'nothing': True}}}, {}),
        ({'feeds': {}}, {}),
        ({'feeds': {'something': 'somevalue'}}, {'something': 'somevalue'})
    ]

    for input, output in matrix:
        assert get_feeds_config(input) == output


def test_get_selected_feeds_to_sync():
    default_result = ['vulnerabilities', 'nvdv2']

    matrix = [
        ({}, default_result),
        ({'feeds': {}}, default_result),
        ({'feeds': None}, default_result),
        ({'feeds': {'selective_sync': {}}}, default_result),
        ({'feeds': {'selective_sync': None}}, default_result),
        ({'feeds': {'selective_sync': {'enabled': False}}}, default_result)
    ]

    for input, output in matrix:
        assert get_selected_feeds_to_sync(input) == output


def test_pivot_and_filter_feeds_by_config(feed_db_records):
    v = [VulnerabilityFeed.__feed_name__]
    v_db = [feed_db_records[VulnerabilityFeed.__feed_name__]]

    v_n = [VulnerabilityFeed.__feed_name__, NvdV2Feed.__feed_name__]
    v_n_db = [feed_db_records[VulnerabilityFeed.__feed_name__], feed_db_records[NvdV2Feed.__feed_name__]]

    n = [NvdV2Feed.__feed_name__]
    n_db = [feed_db_records[NvdV2Feed.__feed_name__]]

    p = [PackagesFeed.__feed_name__]
    p_db = [feed_db_records[PackagesFeed.__feed_name__]]

    matrix = [
        {'to_sync': [], 'source_found': [], 'db_found': [], 'expected_result': {}},
        {
            'to_sync': v,
            'source_found': v,
            'db_found': v_db,
            'expected_result': {VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__]}
        },
        {
            'to_sync': v,
            'source_found': v,
            'db_found': v_n_db,
            'expected_result': {VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__]}
        },
        {
            'to_sync': v,
            'source_found': v_n,
            'db_found': v_n_db,
            'expected_result': {VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__]}
        },
        {
            'to_sync': v_n,
            'source_found': v_n,
            'db_found': v_n_db,
            'expected_result': {
                VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__],
                NvdV2Feed.__feed_name__: feed_db_records[NvdV2Feed.__feed_name__]
            }
        },
        {
            'to_sync': n,
            'source_found': v,
            'db_found': v_db,
            'expected_result': {}
        },
        {
            'to_sync': v,
            'source_found': n,
            'db_found': v_db,
            'expected_result': {}
        },
        {
            'to_sync': v,
            'source_found': n,
            'db_found': p_db,
            'expected_result': {}
        },
        {
            'to_sync': v_n,
            'source_found': v_n,
            'db_found': v_db,
            'expected_result': {
                VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__]
            }
        },
        {
            'to_sync': v_n,
            'source_found': v,
            'db_found': v_n_db,
            'expected_result': {
                VulnerabilityFeed.__feed_name__: feed_db_records[VulnerabilityFeed.__feed_name__]
            }
        },
    ]

    for input in matrix:
        assert DataFeeds._pivot_and_filter_feeds_by_config(input['to_sync'], input['source_found'], input['db_found']) == input['expected_result']