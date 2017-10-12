from __future__ import absolute_import

from docker_registry_client import DockerRegistryClient
from docker_registry_client.Repository import BaseRepository
import pytest
from requests import HTTPError
from tests.mock_registry import (mock_registry,
                                 mock_v2_registry,
                                 TEST_NAMESPACE,
                                 TEST_REPO,
                                 TEST_NAME,
                                 TEST_TAG)


class TestDockerRegistryClient(object):
    @pytest.mark.parametrize('version', [1, 2])
    def test_api_version_in_use(self, version):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        assert client.api_version == version

    @pytest.mark.parametrize('version', [1, 2])
    def test_namespaces(self, version):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        assert client.namespaces() == [TEST_NAMESPACE]

    @pytest.mark.parametrize('version', [1, 2])
    @pytest.mark.parametrize(('repository', 'namespace'), [
        (TEST_REPO, None),
        (TEST_REPO, TEST_NAMESPACE),
        ('{0}/{1}'.format(TEST_NAMESPACE, TEST_REPO), None),
    ])
    def test_repository(self, version, repository, namespace):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        repository = client.repository(repository, namespace=namespace)
        assert isinstance(repository, BaseRepository)

    @pytest.mark.parametrize('version', [1, 2])
    def test_repository_namespace_incorrect(self, version):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        with pytest.raises(RuntimeError):
            client.repository('{0}/{1}'.format(TEST_NAMESPACE, TEST_REPO),
                              namespace=TEST_NAMESPACE)

    @pytest.mark.parametrize('namespace', [TEST_NAMESPACE, None])
    @pytest.mark.parametrize('version', [1, 2])
    def test_repositories(self, version, namespace):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        repositories = client.repositories(TEST_NAMESPACE)
        assert len(repositories) == 1
        assert TEST_NAME in repositories
        repository = repositories[TEST_NAME]
        assert repository.name == "%s/%s" % (TEST_NAMESPACE, TEST_REPO)

    @pytest.mark.parametrize('version', [1, 2])
    def test_repository_tags(self, version):
        url = mock_registry(version)
        client = DockerRegistryClient(url)
        repositories = client.repositories(TEST_NAMESPACE)
        assert TEST_NAME in repositories
        repository = repositories[TEST_NAME]
        tags = repository.tags()
        assert len(tags) == 1
        assert TEST_TAG in tags

    def test_repository_manifest(self):
        url = mock_v2_registry()
        client = DockerRegistryClient(url)
        repository = client.repositories()[TEST_NAME]
        manifest, digest = repository.manifest(TEST_TAG)
        repository.delete_manifest(digest)

    @pytest.mark.parametrize(('client_api_version',
                              'registry_api_version',
                              'should_succeed'), [
        (1, 1, True),
        (2, 2, True),
        (1, 2, False),
        (2, 1, False),
    ])
    def test_api_version(self, client_api_version, registry_api_version,
                         should_succeed):
        url = mock_registry(registry_api_version)
        if should_succeed:
            client = DockerRegistryClient(url, api_version=client_api_version)
            assert client.api_version == client_api_version
        else:
            with pytest.raises(HTTPError):
                client = DockerRegistryClient(url,
                                              api_version=client_api_version)
                client.refresh()
