"""
Tests for the archive subsystem. Tests for each driver are here.
"""
import unittest
import os

from anchore_engine.subsys.object_store.drivers.filesystem import FilesystemObjectStorageDriver
from anchore_engine.subsys.object_store.drivers.rdbms import DbDriver
from anchore_engine.subsys.object_store.drivers.s3 import S3ObjectStorageDriver
from anchore_engine.subsys.object_store.drivers.swift import SwiftObjectStorageDriver
from anchore_engine.subsys import logger

logger.set_log_level('INFO')
logger.enable_bootstrap_logging()

test_s3_key = os.getenv('TEST_ACCESS_KEY')
test_s3_secret_key = os.getenv('TEST_SECRET_KEY')


class TestArchiveDriverMixin(object):
    """
    Expected to be mixed into a unittest.TestCase object
    """
    driver_cls = None
    driver_config = None

    test_obj1 = 'testingdata123'
    test_json_obj1 = {'key1': 'value1'}
    test_user1 = 'testuser1'
    test_user2 = 'testuser2'
    test_bucket1 = 'testbucket1'
    test_bucket2 = 'testbucket2'
    test_archive_id1 = 'testarchiveid1'
    test_archive_id2 = 'testarchiveid2'

    def setUp(self):
        self.driver = self.driver_cls(self.driver_config)

    def test_CRUD(self):
        """
        Test basic CRUD operations
        :return:
        """
        logger.info('Testing CRUD ops for driver: {} w/config: {}'.format(self.driver, self.driver_config))

        self.assertIsNotNone(self.driver.uri_for(userId=self.test_user1, bucket=self.test_bucket1, key=self.test_archive_id1))

        self.assertTrue(self.driver.put(userId=self.test_user1, bucket=self.test_bucket1, key=self.test_archive_id1, data=self.test_obj1), 'Non-True response on put')

        r = self.driver.get(userId=self.test_user1, bucket=self.test_bucket1, key=self.test_archive_id1)

        self.assertEqual(self.test_obj1, r, self.driver)

        self.assertTrue(self.driver.delete(userId=self.test_user1, bucket=self.test_bucket1, key=self.test_archive_id1), 'Non-True response on delete')

        with self.assertRaises(Exception) as ex:
            r = self.driver.get(userId=self.test_user1, bucket=self.test_bucket1, key=self.test_archive_id1)

        logger.info('CRUD test complete for driver: {}'.format(self.driver))


class TestFilesystemArchiveDriver(TestArchiveDriverMixin, unittest.TestCase):
    driver_cls = FilesystemObjectStorageDriver
    driver_config = {
        'archive_data_dir': '/tmp/archive_test/fs_driver'
    }


class TestRDBMSArchiveDriver(TestArchiveDriverMixin, unittest.TestCase):
    driver_cls = DbDriver
    driver_config = {
        'use_db': True,
        'connection_string': None
    }

    @staticmethod
    def setup_engine_config(db_connect_str):
        """
        Sets the config for the service to bootstrap a specific db.
        :param db_connect_str:
        :return:
        """
        from anchore_engine.configuration import localconfig
        localconfig.load_defaults()
        localconfig.localconfig['credentials'] = {
            'database': {
                'db_connect': db_connect_str
            }
        }
        return localconfig.localconfig

    @staticmethod
    def init_db(connect_str='sqlite:///:memory:', do_bootstrap=True):
        """
        Policy-Engine specific db initialization and setup for testing.

        :param connect_str: connection string, defaults to sqllite in-memory if none provided
        :return:
        """
        conf = TestRDBMSArchiveDriver.setup_engine_config(connect_str)
        from anchore_engine.db import initialize, ArchiveDocument, Anchore, ObjectStorageRecord
        from anchore_engine.db.entities.common import do_create
        from anchore_engine.version import version, db_version
        initialize(versions={'service_version': version, 'db_version': db_version}, localconfig=conf)
        do_create(specific_tables=[ArchiveDocument.__table__,  Anchore.__table__, ObjectStorageRecord.__table__])

    @classmethod
    def setUpClass(cls):
        TestRDBMSArchiveDriver.init_db()


class TestS3ArchiveDriver(TestArchiveDriverMixin, unittest.TestCase):
    driver_config = {
        'access_key': test_s3_key,
        'secret_key': test_s3_secret_key,
        'url':'http://localhost:9000',
        'region': None,
        'bucket': 'testarchivebucket'
    }

    driver_cls = S3ObjectStorageDriver


class TestSwiftArchiveDriver(TestArchiveDriverMixin, unittest.TestCase):
    driver_config = {
        'user':'test:tester',
        'key':'testing',
        'auth':'http://localhost:8080/auth/v1.0',
        'container': 'testarchive'
    }

    driver_cls = SwiftObjectStorageDriver


if __name__ == '__main__':
    unittest.main()
