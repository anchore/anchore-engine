import boto3
#import botocore.config
import urllib.parse

from anchore_engine import utils
from anchore_engine.subsys import logger
from .interface import ObjectStorageDriver
from anchore_engine.subsys.object_store.exc import DriverConfigurationError, ObjectKeyNotFoundError, BadCredentialsError

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
        self.s3_client = None
        self.session = None

        # Initialize the client
        # if 'access_key' not in self.config:
        #     raise DriverConfigurationError('Missing access_key in configuration for S3 driver')
        # if 'secret_key' not in self.config:
        #     raise DriverConfigurationError('Missing secret_key in configuration for S3 driver')

        if 'access_key' in self.config and 'secret_key' in self.config:
            self.session = boto3.Session(aws_access_key_id=self.config.get('access_key'),
                                         aws_secret_access_key=self.config.get('secret_key'))
        elif self.config.get('iamauto'):
            self.session = boto3.Session()
        else:
            raise DriverConfigurationError('Missing either "access_key" and "secret_key" configuration values or "iamauto"=True in configuration for credentials')

        if 'url' in self.config:
            self.endpoint = self.config.get('url')
            if not self.endpoint:
                raise DriverConfigurationError('Missing valid value for configuration parameter "url" ({})'.format(self.endpoint))

            self.s3_client = self.session.client(service_name='s3', endpoint_url=self.config.get('url'))
        elif 'region' in self.config:
            self.region = self.config.get('region')
            if not self.region:
                raise DriverConfigurationError('Missing valid value for configuration parameter "region" ({})'.format(self.region))
            self.s3_client = self.session.client(service_name='s3', region_name=self.config.get('region'))
        else:
            self.s3_client = self.session.client(service_name='s3')

        self.bucket_name = self.config.get('bucket')
        self.create_bucket = self.config.get('create_bucket', False)
        if not self.bucket_name:
            raise ValueError('Cannot configure s3 driver with out a provided bucket to use')

        self._check_creds()
        self._check_bucket()

        self.prefix = self.config.get('prefix', '')

    def _check_creds(self):
        try:
            self.s3_client.get_bucket_location(Bucket=self.bucket_name)
        except Exception as ex:
            if type(ex).__name__ == 'ClientError' and hasattr(ex, 'response') and ex.response.get('ResponseMetadata', {}).get('HTTPStatusCode') in [403, 401]:
                raise BadCredentialsError(creds_dict=self.session.get_credentials().__dict__, endpoint=self.s3_client._endpoint, cause=ex)

    def _check_bucket(self):
        try:
            self.s3_client.get_bucket_location(Bucket=self.bucket_name)
        except Exception as ex:
            if type(ex).__name__ == 'NoSuchBucket' and self.create_bucket:
                self.s3_client.create_bucket(Bucket=self.bucket_name)
            else:
                logger.error(
                    'Error checking configured bucket for location during driver preflight check. Bucket = {}. Error = {}'.format(
                        self.bucket_name, ex))
                raise DriverConfigurationError(cause=ex)

    def _build_key(self, userId, usrBucket, key):
        return self._key_format.format(prefix=self.prefix, userid=userId, bucket=usrBucket, key=key)

    def get(self, userId, bucket, key):
        uri = self.uri_for(userId, bucket, key)
        return self.get_by_uri(uri)

    def _parse_uri(self, uri):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        bucket = parsed.hostname
        key = parsed.path[1:]
        return bucket, key

    def get_by_uri(self, uri):
        bucket, key = self._parse_uri(uri)
        try:
            resp = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = resp['Body'].read()
            ret = utils.ensure_bytes(content)
            return(ret)
            
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
