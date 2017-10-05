import docker_registry_client


def test_exported_symbols():
    assert hasattr(docker_registry_client, 'DockerRegistryClient')
    assert hasattr(docker_registry_client, 'BaseClient')
    assert hasattr(docker_registry_client, 'Repository')
