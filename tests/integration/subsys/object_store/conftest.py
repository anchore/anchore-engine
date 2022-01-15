import os

import pytest

from anchore_engine.subsys import logger

test_s3_key = os.getenv("ANCHORE_TEST_S3_ACCESS_KEY")
test_s3_secret_key = os.getenv("ANCHORE_TEST_S3_SECRET_KEY")
test_s3_url = os.getenv("ANCHORE_TEST_S3_URL")
test_s3_region = os.getenv("ANCHORE_TEST_S3_REGION")
test_s3_bucket = os.getenv("ANCHORE_TEST_S3_BUCKET")

test_swift_user = os.getenv("ANCHORE_TEST_SWIFT_USER")
test_swift_key = os.getenv("ANCHORE_TEST_SWIFT_KEY")
test_swift_auth_url = os.getenv("ANCHORE_TEST_SWIFT_AUTH_URL")
test_swift_container = os.getenv("ANCHORE_TEST_SWIFT_CONTAINER")


@pytest.fixture
def s3_client():
    import boto3

    logger.info("Initializing an s3 bucket: {}".format(test_s3_bucket))

    session = boto3.Session(
        aws_access_key_id=test_s3_key, aws_secret_access_key=test_s3_secret_key
    )

    if test_s3_url:
        client = session.client(service_name="s3", endpoint_url=test_s3_url)

    elif test_s3_region:
        client = session.client(service_name="s3", region_name=test_s3_region)
    else:
        client = session.client(service_name="s3")
    return client


@pytest.fixture(scope="module")
def s3_bucket():
    """
    Provides a bucket in the configured s3 endpoint for testing. Yields name, on exit will delete the bucket
    :return: yields a string name
    """
    import boto3
    import botocore.exceptions

    logger.info("Initializing an s3 bucket: {}".format(test_s3_bucket))

    bucket_name = test_s3_bucket
    session = boto3.Session(
        aws_access_key_id=test_s3_key, aws_secret_access_key=test_s3_secret_key
    )

    if test_s3_url:
        s3_client = session.client(service_name="s3", endpoint_url=test_s3_url)

    elif test_s3_region:
        s3_client = session.client(service_name="s3", region_name=test_s3_region)
    else:
        s3_client = session.client(service_name="s3")

    try:
        try:
            s3_client.create_bucket(Bucket=bucket_name)
        except:
            pass

        yield bucket_name, s3_client
    finally:
        logger.info("Deleting/cleanup s3 bucket: {}".format(test_s3_bucket))
        try:
            for _obj in s3_client.list_objects(Bucket=bucket_name).get("Contents", []):
                s3_client.delete_object(Bucket=bucket_name, Key=_obj["Key"])
            s3_client.delete_bucket(Bucket=bucket_name)
        except botocore.exceptions.ClientError as e:
            logger.exception("Bucket cleanup exception")
            if e.response.get("Code") == "BucketNotEmpty":
                logger.warn("Cannot clean up bucket {}, not empty".format(bucket_name))
            else:
                logger.warn(
                    "Error cleaning up bucket {}, may result in other test failures".format(
                        bucket_name
                    )
                )


@pytest.fixture(scope="module")
def swift_container():
    from swiftclient.service import SwiftService

    container_name = test_swift_container

    # Initialize the client
    v1_client_config = {
        "user": test_swift_user,
        "key": test_swift_key,
        "auth": test_swift_auth_url,
    }

    client = SwiftService(options=v1_client_config)

    try:
        logger.info("Initializing a swift container: {}".format(test_swift_container))
        client.post(container=container_name)
        yield container_name, client
    finally:
        logger.info(
            "Deleting/cleanup a swift container: {}".format(test_swift_container)
        )
        try:
            client.delete(container=container_name)
        except Exception as e:
            logger.exception("Container cleanup exception")
            logger.warn(
                "Error cleaning up swift container {}, may result in other test failures".format(
                    container_name
                )
            )
