from __future__ import absolute_import

from flexmock import flexmock
from docker_registry_client import _BaseClient
import json
from requests.exceptions import HTTPError
from requests.models import Response


REGISTRY_URL = "https://registry.example.com:5000"
TEST_NAMESPACE = 'library'
TEST_REPO = 'myrepo'
TEST_NAME = '%s/%s' % (TEST_NAMESPACE, TEST_REPO)
TEST_TAG = 'latest'
TEST_MANIFEST_DIGEST = '''\
sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b'''


class MockResponse(object):
    def __init__(self, code, data=None, text=None, headers=None):
        self.ok = (code >= 200 and code < 400)
        self.status_code = code
        self.data = data
        self.text = text or ''
        self.headers = headers or {}
        self.reason = ''

    @property
    def content(self):
        if self.data is None:
            return None

        return json.dumps(self.data).encode()

    def raise_for_status(self):
        if not self.ok:
            response = Response()
            response.status_code = self.status_code
            raise HTTPError(response=response)

    def json(self):
        return self.data


class MockRegistry(object):
    GET_MAP = {}
    DELETE_MAP = {}

    @staticmethod
    def format(s):
        return s.format(namespace=TEST_NAMESPACE,
                        repo=TEST_REPO,
                        name=TEST_NAME,
                        tag=TEST_TAG,
                        digest=TEST_MANIFEST_DIGEST)

    def call(self, response_map, url, data=None, headers=None):
        assert url.startswith(REGISTRY_URL)
        request = self.format(url[len(REGISTRY_URL):])
        try:
            return response_map[request]
        except KeyError:
            return MockResponse(code=404, text='Not found: %s' % request)

    def get(self, *args, **kwargs):
        return self.call(self.GET_MAP, *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self.call(self.DELETE_MAP, *args, **kwargs)


class MockV1Registry(MockRegistry):
    TAGS = MockRegistry.format('/v1/repositories/{namespace}/{repo}/tags')
    TAGS_LIBRARY = MockRegistry.format('/v1/repositories/{repo}/tags')

    GET_MAP = {
        '/v1/_ping': MockResponse(200),

        '/v1/search': MockResponse(200, data={
            'results': [{'name': '%s/%s' % (TEST_NAMESPACE, TEST_REPO)}]}),

        TAGS: MockResponse(200, data={TEST_TAG: ''}),

        TAGS_LIBRARY: MockResponse(200, data={TEST_TAG: ''}),
    }


def mock_v1_registry():
    v1_registry = MockV1Registry()
    flexmock(_BaseClient, get=v1_registry.get)
    return REGISTRY_URL


class MockV2Registry(MockRegistry):
    TAGS = MockRegistry.format('/v2/{name}/tags/list')
    TAGS_LIBRARY = MockRegistry.format('/v2/{repo}/tags/list')
    MANIFEST_TAG = MockRegistry.format('/v2/{name}/manifests/{tag}')
    MANIFEST_DIGEST = MockRegistry.format('/v2/{name}/manifests/{digest}')

    GET_MAP = {
        '/v2/': MockResponse(200),

        '/v2/_catalog': MockResponse(200, data={'repositories': [TEST_NAME]}),

        TAGS:
        MockResponse(200, data={'name': TEST_NAME,
                                'tags': [TEST_TAG]}),

        TAGS_LIBRARY:
        MockResponse(200, data={'name': TEST_NAME,
                                'tags': [TEST_TAG]}),

        MANIFEST_TAG:
        MockResponse(200,
                     data={
                         'name': TEST_NAME,
                         'tag': TEST_TAG,
                         'fsLayers': []
                     },
                     headers={
                         'Docker-Content-Digest': TEST_MANIFEST_DIGEST,
                     }),
    }

    DELETE_MAP = {
        MANIFEST_DIGEST: MockResponse(202, data={}),
    }


def mock_v2_registry():
    v2_registry = MockV2Registry()
    flexmock(_BaseClient,
             get=v2_registry.get,
             delete=v2_registry.delete)
    return REGISTRY_URL


def mock_registry(version):
    if version == 1:
        return mock_v1_registry()
    elif version == 2:
        return mock_v2_registry()
    else:
        raise NotImplementedError()
