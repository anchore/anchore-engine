from legacy_test import init_test_logging
import unittest, logging
import time
from legacy_test.services.policy_engine import NewDBPerTestUnitTest

init_test_logging(level=logging.DEBUG)

from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.db import Vulnerability, FixedArtifact, VulnerableArtifact, GemMetadata, NpmMetadata, session_scope

log = get_logger()

reason = 'only packages'

class FeedTest(NewDBPerTestUnitTest):
    @classmethod
    def setUpClass(cls):
        super(FeedTest, cls).setUpClass()
        cls.test_env.init_feeds()

    #@unittest.skip(reason)
    def test_vuln_sync(self):
        print('Test0')
        with session_scope() as db:
            vcount = db.query(Vulnerability).count()

        log.info('Starting with {} vuln records'.format(vcount))
        self.assertEqual(vcount, 0, 'Not starting with empty table')

        df = DataFeeds.instance()
        log.info('Syncing vulnerabilities')
        t = time.time()
        df.vulnerabilities.sync(group='alpine:3.3')
        t = time.time() - t
        log.info('Done with vulnerabilities. Took: {} sec'.format(t))
        with session_scope() as db:
            log.info('Has {} vuln records'.format(db.query(Vulnerability).count()))


    @unittest.skip(reason)
    def test_bulk_vuln_sync(self):
        with session_scope() as db:
            vcount = db.query(Vulnerability).count()
            log.info('Starting with {} vuln records'.format(vcount))
            self.assertEqual(vcount, 0, 'Not starting with empty table')

        df = DataFeeds.instance()
        t = time.time()
        df.vulnerabilities.bulk_sync()
        t = time.time() - t
        log.info('Done with vulnerabilities. Took: {} sec'.format(t))
        log.info('Has {} vuln records'.format(db.query(Vulnerability).count()))

    @unittest.skip(reason)
    def test_package_sync(self):
        with session_scope() as db:
            ncount = db.query(NpmMetadata).count()
            gcount = db.query(GemMetadata).count()
        self.assertEqual(ncount, 0, 'Not starting with empty table')
        self.assertEqual(gcount, 0, 'Not starting with empty table')

        df = DataFeeds.instance()
        log.info('Syncing packages')
        t = time.time()
        df.packages.sync()
        t = time.time() - t
        log.info('Done with packages. Took: {} sec'.format(t))
        with session_scope() as db:
            ncount = db.query(NpmMetadata).count()
            gcount = db.query(GemMetadata).count()

        log.info('Has {} npm records'.format(ncount))
        log.info('Has {} gem records'.format(gcount))

    @unittest.skip(reason)
    def test_bulk_package_sync(self):
        with session_scope() as db:
            ncount = db.query(NpmMetadata).count()
            gcount = db.query(GemMetadata).count()
        self.assertEqual(ncount, 0, 'Not starting with empty table')
        self.assertEqual(gcount, 0, 'Not starting with empty table')

        df = DataFeeds.instance()
        t = time.time()
        df.packages.bulk_sync()
        t = time.time() - t
        log.info('Done with bulk package sync. Took: {} sec'.format(t))
        with session_scope() as db:
            ncount = db.query(NpmMetadata).count()
            gcount = db.query(GemMetadata).count()

        log.info('Has {} npm records'.format(ncount))
        log.info('Has {} gem records'.format(gcount))

    @unittest.skip(reason)
    def test_group_lookups(self):
        df = DataFeeds.instance()
        df.vulnerabilities.refresh_groups()
        bad = df.vulnerabilities.group_by_name('not_a_real_Group')
        self.assertFalse(bad, 'Found non-existent group')
        self.assertIsNotNone(df.vulnerabilities.group_by_name('alpine:3.3'), 'Should have found group alpine:3.3')



