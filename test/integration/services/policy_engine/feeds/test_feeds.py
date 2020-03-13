import time
import pytest

from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.services.policy_engine.engine.feeds.feeds import feed_instance_by_name
from anchore_engine.services.policy_engine.engine.feeds.download import LocalFeedDataRepo, LocalFeedDataRepoMetadata
from anchore_engine.db import Vulnerability, GemMetadata, NpmMetadata, session_scope

logger.enable_test_logging()

reason = 'only packages'

empty_metadata_sync_result = ({}, []) # No feeds synced nor requested so no errors

def test_vuln_sync(test_data_env):
    with session_scope() as db:
        vcount = db.query(Vulnerability).count()

    logger.info('Starting with {} vuln records'.format(vcount))
    assert vcount == 0, 'Not starting with empty table'

    logger.info('Syncing vulnerabilities')
    t = time.time()
    DataFeeds.__scratch_dir__ = '/tmp'
    DataFeeds.sync(to_sync=['vulnerabilities'], feed_client=test_data_env.feed_client)

    t = time.time() - t
    logger.info('Done with vulnerabilities. Took: {} sec'.format(t))
    with session_scope() as db:
        logger.info('Has {} vuln records'.format(db.query(Vulnerability).count()))


def test_package_sync(test_data_env):
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()
    assert ncount == 0, 'Not starting with empty table'
    assert gcount == 0, 'Not starting with empty table'

    logger.info('Syncing packages')
    t = time.time()
    DataFeeds.__scratch_dir__ = '/tmp'
    DataFeeds.sync(to_sync=['packages'], feed_client=test_data_env.feed_client)
    t = time.time() - t
    logger.info('Done with packages. Took: {} sec'.format(t))
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()

    logger.info('Has {} npm records'.format(ncount))
    logger.info('Has {} gem records'.format(gcount))


def test_group_lookups(test_data_env):
    r = DataFeeds.sync_metadata(feed_client=test_data_env.feed_client)
    assert r == empty_metadata_sync_result, 'No metadata should be returned from sync with empty to_sync input'

    r = DataFeeds.sync_metadata(feed_client=test_data_env.feed_client, to_sync=['vulnerabilities'])
    assert r and len(r[0]) == 1, 'Metadata should be returned from sync with non-empty to_sync list'

    df = feed_instance_by_name('vulnerabilities')
    assert df is not None, 'vulnerabilities feed instance not loaded'
    assert df.metadata, 'No vuln metadata found'
    logger.info('Vuln feed metadata {}'.format(df.metadata.to_json()))
    assert not df.group_by_name('not_a_real_Group'), 'Found non-existent group'
    assert df.group_by_name('alpine:3.6'), 'Should have found group alpine:3.6'


def test_sync_repo(test_data_env):
    repo = LocalFeedDataRepo.from_disk('test/data/feeds_repo')
    assert repo.has_metadata(), 'Repo should have metadata'
    assert repo.has_root(), 'Repo should have root dir already'
    with pytest.raises(Exception):
        DataFeeds.sync_from_fetched(repo, catalog_client=None)

    assert DataFeeds.sync_metadata(feed_client=test_data_env.feed_client) == empty_metadata_sync_result
    assert DataFeeds.sync_metadata(feed_client=test_data_env.feed_client, to_sync=['vulnerabilities'])[0].get('vulnerabilities') is not None
    assert DataFeeds.sync_from_fetched(repo, catalog_client=None)


def test_metadata_sync(test_data_env):
    r = DataFeeds.sync_metadata(feed_client=test_data_env.feed_client)
    assert r == empty_metadata_sync_result, 'Expected empty dict result from metadata sync with no to_sync directive'

    r = DataFeeds.sync_metadata(feed_client=test_data_env.feed_client, to_sync=['vulnerabilities', 'packages', 'vulndb', 'nvdv2'])
    assert r is not None, 'Expected dict result from metadata sync'
    assert type(r) == tuple and type(r[0]) == dict and type(r[1]) == list, 'Expected tuple with element 1 = dict result from metadata sync'
    assert len(r[0]) == 4, 'Expected dict result from metadata sync'
    assert r[0].get('vulnerabilities')
    assert r[0].get('packages')
    assert r[0].get('vulndb')
    assert r[0].get('nvdv2')

