import time

from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.db import Vulnerability, GemMetadata, NpmMetadata, session_scope
from test.fixtures import anchore_db
from test.integration.services.policy_engine.fixtures import test_data_env

logger.enable_test_logging()

reason = 'only packages'


def test_vuln_sync(test_data_env):
    print('Test0')
    with session_scope() as db:
        vcount = db.query(Vulnerability).count()

    logger.info('Starting with {} vuln records'.format(vcount))
    assert vcount == 0, 'Not starting with empty table'

    df = DataFeeds.instance()
    logger.info('Syncing vulnerabilities')
    t = time.time()
    df.vulnerabilities.sync(group='alpine:3.3')
    t = time.time() - t
    logger.info('Done with vulnerabilities. Took: {} sec'.format(t))
    with session_scope() as db:
        logger.info('Has {} vuln records'.format(db.query(Vulnerability).count()))


def test_bulk_vuln_sync(test_data_env):
    with session_scope() as db:
        vcount = db.query(Vulnerability).count()
        logger.info('Starting with {} vuln records'.format(vcount))
        assert vcount == 0, 'Not starting with empty table'

    df = DataFeeds.instance()
    t = time.time()
    df.vulnerabilities.bulk_sync()
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

    df = DataFeeds.instance()
    logger.info('Syncing packages')
    t = time.time()
    df.packages.sync()
    t = time.time() - t
    logger.info('Done with packages. Took: {} sec'.format(t))
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()

    logger.info('Has {} npm records'.format(ncount))
    logger.info('Has {} gem records'.format(gcount))


def test_bulk_package_sync(test_data_env):
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()
    assert ncount == 0, 'Not starting with empty table'
    assert gcount == 0, 'Not starting with empty table'

    df = DataFeeds.instance()
    t = time.time()
    df.packages.bulk_sync()
    t = time.time() - t
    logger.info('Done with bulk package sync. Took: {} sec'.format(t))
    with session_scope() as db:
        ncount = db.query(NpmMetadata).count()
        gcount = db.query(GemMetadata).count()

    logger.info('Has {} npm records'.format(ncount))
    logger.info('Has {} gem records'.format(gcount))


def test_group_lookups(test_data_env):
    df = DataFeeds.instance()
    df.vulnerabilities.refresh_groups()
    bad = df.vulnerabilities.group_by_name('not_a_real_Group')
    assert not bad, 'Found non-existent group'
    assert df.vulnerabilities.group_by_name('alpine:3.3') is not None, 'Should have found group alpine:3.3'
