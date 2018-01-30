import boto3
import urlparse

from .interface import ObjectStorageDriver
from anchore_engine.subsys.object_store.exc import DriverConfigurationError, ObjectKeyNotFoundError

class S3ObjectStorageDriver(ObjectStorageDriver):
    """
    Archive driver using s3-api as backing store.

    Buckets presented as part of object lookup in this API are mapped to object key prefixes in the backing S3 store so that a single bucket (or set of buckets)
    can be used since namespaces are limited.

    """
    __config_name__ = 's3'
    __driver_version__ = '1'
    __uri_scheme__ = 's3'

    _key_format = '{prefix}{userid}/{bucket}/{key}'

    def __init__(self, config):
        super(S3ObjectStorageDriver, self).__init__(config)

        self.endpoint = None
        self.region = None

        # Initialize the client
        if 'access_key' not in self.config:
            raise DriverConfigurationError('Missing access_key in configuration for S3 driver')
        if 'secret_key' not in self.config:
            raise DriverConfigurationError('Missing secret_key in configuration for S3 driver')

        if 'url' in self.config:
            self.endpoint = self.config.get('url')
            self.session = boto3.Session(aws_access_key_id = self.config.get('access_key'), aws_secret_access_key = self.config.get('secret_key'))
            self.s3_client = self.session.client(service_name='s3', endpoint_url=self.config.get('url'))
        elif 'region' in self.config:
            self.region = self.config.get('region')
            self.session = boto3.Session(aws_access_key_id=self.config.get('access_key'), aws_secret_access_key=self.config.get('secret_key'))
            self.s3_client = self.session.client(service_name='s3', region_name=self.config.get('region'))
        else:
            raise DriverConfigurationError('No region or url specified for s3 driver. Set a region for AWS or url for s3-api service')

        self.bucket_name = self.config.get('bucket')
        if not self.bucket_name:
            raise ValueError('Cannot configure s3 driver with out a provided bucket to use')

        self.prefix = self.config.get('prefix', '')

    def _build_key(self, userId, usrBucket, key):
        return self._key_format.format(prefix=self.prefix, userid=userId, bucket=usrBucket, key=key)

    def get(self, userId, bucket, key):
        uri = self.uri_for(userId, bucket, key)
        return self.get_by_uri(uri)

    def _parse_uri(self, uri):
        parsed = urlparse.urlparse(uri, scheme=self.__uri_scheme__)
        bucket = parsed.hostname
        key = parsed.path[1:]
        return bucket, key

    def get_by_uri(self, uri):
        bucket, key = self._parse_uri(uri)
        try:
            resp = self.s3_client.get_object(Bucket=bucket, Key=key)
            return resp['Body'].read()
        except Exception as e:
            raise e

    def put(self, userId, bucket, key, data):
        gen_key = self._build_key(userId, bucket, key)
        try:
            resp = self.s3_client.put_object(Bucket=self.bucket_name, Key=gen_key,
                                             ContentType='binary/octet-stream', Body=data)
            if resp:
                return self.uri_for(userId, bucket, key)
            raise Exception('Failed to write object to s3')
        except Exception as e:
            raise e

    def delete(self, userId, bucket, key):
        uri = self.uri_for(userId, bucket, key)
        return self.delete_by_uri(uri)

    def delete_by_uri(self, uri):
        bucket, key = self._parse_uri(uri)
        try:
            resp = self.s3_client.delete_object(Bucket=bucket, Key=key)
            return True
        except Exception as e:
            raise e

    def uri_for(self, userId, bucket, key):
        return '{}://{}/{}'.format(self.__uri_scheme__, self.bucket_name, self._build_key(userId, bucket, key))
