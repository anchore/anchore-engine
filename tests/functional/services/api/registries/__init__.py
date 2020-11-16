import os


def get_registry_info():
    return {
        "user": os.environ.get("ANCHORE_TEST_DOCKER_REGISTRY_USER", "anchore"),
        "pass": os.environ.get("ANCHORE_TEST_DOCKER_REGISTRY_PASS", "foobar"),
        "host": os.environ.get("ANCHORE_TEST_DOCKER_REGISTRY_HOST", "localhost:5000"),
        "service_name": "docker-registry:5000",
    }
