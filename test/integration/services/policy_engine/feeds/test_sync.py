from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.subsys import logger

logger.enable_test_logging()


def test_sync_fail(test_data_env):
    DataFeeds.__scratch_dir__ = '/tmp'
    # No such feed
    result = DataFeeds.sync(to_sync=['nvd'], feed_client=test_data_env.feed_client)
    assert len(result) == 1
    assert result[0]['status'] == 'failure'

    DataFeeds.__scratch_dir__ = '/tmp'
    result = DataFeeds.sync(to_sync=['vulnerabilities', 'packages', 'nvdv2', 'vulndb'], feed_client=test_data_env.feed_client)
    assert len(result) == 4
    assert not any(filter(lambda x: x['status'] == 'failure', result))

