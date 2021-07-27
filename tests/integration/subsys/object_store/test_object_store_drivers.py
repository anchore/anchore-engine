"""
Tests for the archive subsystem. Tests for each driver are here.
"""
import pytest

from anchore_engine.subsys import logger
from anchore_engine.subsys.object_store import exc
from anchore_engine.subsys.object_store.drivers.filesystem import (
    FilesystemObjectStorageDriver,
)
from anchore_engine.subsys.object_store.drivers.rdbms import DbDriver
from anchore_engine.subsys.object_store.drivers.s3 import S3ObjectStorageDriver
from anchore_engine.subsys.object_store.drivers.swift import SwiftObjectStorageDriver
from tests.integration.subsys.object_store.conftest import (
    test_s3_bucket,
    test_s3_key,
    test_s3_region,
    test_s3_secret_key,
    test_s3_url,
    test_swift_auth_url,
    test_swift_container,
    test_swift_key,
    test_swift_user,
)


class TestS3OjbectStorageDriver:
    def setup(self):
        self.driver_config = {
            "access_key": test_s3_key,
            "secret_key": test_s3_secret_key,
            "url": test_s3_url,
            "region": test_s3_region,
            "bucket": test_s3_bucket,
        }

    def test_check_is_valid(self, s3_bucket):
        S3ObjectStorageDriver(self.driver_config)

    def test_key_is_removed(self, s3_bucket, s3_client):
        S3ObjectStorageDriver(self.driver_config)
        response = s3_client.list_objects_v2(Bucket=test_s3_bucket)
        assert response.get("Contents") is None

    def test_403(self, s3_bucket):
        self.driver_config["access_key"] = "bogus"
        with pytest.raises(exc.BadCredentialsError):
            S3ObjectStorageDriver(self.driver_config)

    def test_400(self, s3_bucket):
        self.driver_config["secret_key"] = "bogus"
        with pytest.raises(exc.BadCredentialsError):
            S3ObjectStorageDriver(self.driver_config)

    def test_404(self, s3_bucket):
        self.driver_config["bucket"] = "bogus"
        with pytest.raises(exc.BucketNotFoundError):
            S3ObjectStorageDriver(self.driver_config)

    def test_non_boto_error(self, s3_bucket):
        self.driver_config["bucket"] = lambda x: None
        with pytest.raises(AttributeError):
            S3ObjectStorageDriver(self.driver_config)


def do_test_CRUD(driver_cls, driver_config):
    """
    Expected to be mixed into a unittest.TestCase object
    """

    test_obj1 = b"testingdata123"
    test_user1 = "testuser1"
    test_user2 = "testuser2"
    test_bucket1 = "testbucket1"
    test_bucket2 = "testbucket2"
    test_archive_id1 = "testarchiveid1"
    test_archive_id2 = "testarchiveid2"

    driver = driver_cls(driver_config)

    logger.info(
        "Testing CRUD ops for driver: {} w/config: {}".format(driver, driver_config)
    )

    assert (
        driver.uri_for(userId=test_user1, bucket=test_bucket1, key=test_archive_id1)
        is not None
    )

    assert driver.put(
        userId=test_user1, bucket=test_bucket1, key=test_archive_id1, data=test_obj1
    ), "Non-True response on put"

    r = driver.get(userId=test_user1, bucket=test_bucket1, key=test_archive_id1)

    assert test_obj1 == r, driver

    assert driver.delete(
        userId=test_user1, bucket=test_bucket1, key=test_archive_id1
    ), "Non-True response on delete"

    with pytest.raises(Exception) as ex:
        r = driver.get(userId=test_user1, bucket=test_bucket1, key=test_archive_id1)

    logger.info("CRUD test complete for driver: {}".format(driver))


def test_fs_driver(anchore_db):
    driver_cls = FilesystemObjectStorageDriver
    driver_config = {"archive_data_dir": "/tmp/archive_test/fs_driver"}

    do_test_CRUD(driver_cls, driver_config)


def test_db_driver(anchore_db):
    driver_cls = DbDriver
    driver_config = {"use_db": True, "connection_string": None}

    do_test_CRUD(driver_cls, driver_config)


def test_s3_driver(s3_bucket, anchore_db):
    driver_config = {
        "access_key": test_s3_key,
        "secret_key": test_s3_secret_key,
        "url": test_s3_url,
        "region": test_s3_region,
        "bucket": test_s3_bucket,
    }

    driver_cls = S3ObjectStorageDriver

    do_test_CRUD(driver_cls, driver_config)


def test_swift_driver(swift_container, anchore_db):
    driver_config = {
        "user": test_swift_user,
        "key": test_swift_key,
        "auth": test_swift_auth_url,
        "container": test_swift_container,
    }

    driver_cls = SwiftObjectStorageDriver

    do_test_CRUD(driver_cls, driver_config)
