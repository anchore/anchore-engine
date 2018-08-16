import copy
import json
import urllib.parse
import io
from swiftclient.service import SwiftService, SwiftUploadObject, SwiftError

from anchore_engine import utils
from anchore_engine.subsys.object_store.drivers.interface import ObjectStorageDriver
from anchore_engine.subsys.object_store.exc import DriverBackendError, DriverConfigurationError, ObjectKeyNotFoundError, ObjectStorageDriverError, BadCredentialsError
from anchore_engine.subsys import logger


# Deal with the verbose logging verbosity of swiftclient
import logging
l = logging.getLogger('swiftclient')
l.setLevel(logging.WARN)


class SwiftObjectStorageDriver(ObjectStorageDriver):
    """
    Archive driver using swift-api as backing store.

    Buckets presented as part of object lookup in this API are mapped to object key prefixes in the backing S3 store so that a single bucket (or set of buckets)
    can be used since namespaces are limited.

    """
    __config_name__ = 'swift'
    __driver_version__ = '1'
    __uri_scheme__ = 'swift'

    _key_format = '{prefix}{userid}/{container}/{key}'
    DEFAULT_AUTH_TIMEOUT = 10

    def __init__(self, config):
        super(SwiftObjectStorageDriver, self).__init__(config)

        # Initialize the client
        self.client_config = config
        self.container_name = self.config.get('container')
        self.can_create_container = self.config.get('create_container', False)
        self.auth_options = copy.copy(self.client_config)
        if 'container' in self.auth_options:
            self.auth_options.pop('container')
        if 'create_container' in self.auth_options:
            self.auth_options.pop('create_container')
        self.client = SwiftService(options=self.auth_options)

        if not self.container_name:
            raise ValueError('Cannot configure swift driver with out a provided container to use')

        self.prefix = self.config.get('anchore_key_prefix', '')

        self._check_creds()
        self._check_container()

    def _check_creds(self):
        """
        Simple operation to verify creds work without state change
        :return: True on success
        """
        try:
            resp = self.client.stat()
            if resp['success']:
                return True
            elif resp.get('error') and resp.get('error').http_status in [401, 403]:
                raise BadCredentialsError(self.auth_options, endpoint=None, cause=resp.get('error'))
            elif resp.get('error'):
                raise DriverConfigurationError(cause=resp.get('error'))
            else:
                raise DriverConfigurationError(Exception('Got unsuccessful response from stat operation against service: {}'.format(resp)))
        except SwiftError as e:
            raise DriverConfigurationError(e)

    def _check_container(self):
        try:
            resp = self.client.stat(container=self.container_name)
        except SwiftError as e:
            if e.exception.http_status == 404 and self.can_create_container:
                try:
                    self.client.post(container=self.container_name)
                except Exception as e:
                    logger.exception(e)
                    raise e
            else:
                raise e

    def _build_key(self, userId, usrBucket, key):
        return self._key_format.format(prefix=self.prefix, userid=userId, container=usrBucket, key=key)

    def _parse_uri(self, uri):
        parsed = urllib.parse.urlparse(uri, scheme=self.__uri_scheme__)
        container = parsed.hostname
        key = parsed.path[1:] # Strip leading '/'
        return container, key

    def get_by_uri(self, uri):
        try:
            container, key = self._parse_uri(uri)
            if container != self.container_name:
                logger.warn('Container mismatch between content_uri and configured cotnainer name: {} in db record, but {} in config'.format(container, self.container_name))

            resp = self.client.download(container=container, objects=[key], options={'out_file': '-'})
            for obj in resp:
                if 'contents' in obj and obj['action'] == 'download_object':
                    content = b''.join([x for x in obj['contents']])
                    ret = utils.ensure_bytes(content)     
                    return (ret)
                elif obj['action'] == 'download_object' and not obj['success']:
                    raise ObjectKeyNotFoundError(bucket='', key='', userId='', caused_by=None)
                raise Exception('Unexpected operation/action from swift: {}'.format(obj['action']))
        except SwiftError as e:
            raise ObjectStorageDriverError(cause=e)

    def delete_by_uri(self, uri):
        try:
            container, key = self._parse_uri(uri)
            if container != self.container_name:
                logger.warn('Container mismatch between content_uri and configured bucket name: {} in db record, but {} in config'.format(container, self.container_name))

            resp = self.client.delete(container=container, objects=[key])
            for r in resp:
                if r['success'] and r['action'] == 'delete_object':
                    return True
        except Exception as e:
            raise e

    def exists(self, uri):
        try:
            container, key = self._parse_uri(uri)
            if container != self.container_name:
                logger.warn('Bucket mismatch between content_uri and configured bucket name: {} in db record, but {} in config'.format(container, self.container_name))

            resp = self.client.download(container=container, objects=[key], options={'out_file': '-', 'no_download': True})
            for obj in resp:
                if 'success' in obj and obj['success'] and obj['action'] == 'download_object':
                    return True
                elif obj['action'] == 'download_object' and not obj['success']:
                    return False
                raise Exception('Unexpected operation/action from swift: {}'.format(obj['action']))
        except SwiftError as e:
            raise ObjectStorageDriverError(cause=e)

    def get(self, userId, bucket, key):
        return self.get_by_uri(self.uri_for(userId, bucket, key))

    def put(self, userId, bucket, key, data):
        try:
            uri = self.uri_for(userId, bucket, key)
            swift_bucket, swift_key = self._parse_uri(uri)
            obj = SwiftUploadObject(object_name=swift_key, source=io.BytesIO(data))
            resp = self.client.upload(container=swift_bucket, objects=[obj])
            for upload in resp:
                if upload['action'] == 'upload_object' and upload['success']:
                    return uri
            else:
                raise Exception('Failed uploading object to swift')
        except Exception as e:
            raise e

    def delete(self, userId, bucket, key):
        return self.delete_by_uri(self.uri_for(userId, bucket, key))

    def uri_for(self, userId, bucket, key):
        return '{}://{}/{}'.format(self.__uri_scheme__, self.container_name, self._build_key(userId, bucket, key))
