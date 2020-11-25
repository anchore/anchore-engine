import os


def get_registry_info():
    return {
        "user": os.environ["ANCHORE_TEST_DOCKER_REGISTRY_USER"],
        "pass": os.environ["ANCHORE_TEST_DOCKER_REGISTRY_PASS"],
        "host": os.environ["ANCHORE_TEST_DOCKER_REGISTRY_HOST"],
        "service_name": "docker-registry:5000",
    }
