import os

import docker
import pytest
from docker.errors import DockerException


def use_environ():
    """
    In certain test environments, the necessary docker env vars are available
    and those should be used. This function checks for those and returns
    a boolean so that the docker client can be instantiated properly
    """
    for var in [
        "DOCKER_CERT_PATH",
        "DOCKER_HOST",
        "DOCKER_MACHINE_NAME",
        "DOCKER_TLS_VERIFY",
    ]:
        if os.environ.get(var) is None:
            return False
    return True


def run(client):
    """
    Provide a wrapper for running a Docker Command through the Docker client
    :param client: Docker client (initialized from environment or talks to the unix socket directly)
    """

    def run_command(container_id, command):
        """
        Returns a callable function that runs Docker Command via the Docker client for a specific container
        :param container_id: Docker Container
        :param command: The command to run within the container
        """
        created_command = client.exec_create(container_id, cmd=command)
        result = client.exec_start(created_command)
        exit_code = client.exec_inspect(created_command)["ExitCode"]
        if exit_code != 0:
            msg = "Non-zero exit code (%d) for command: %s" % (exit_code, command)
            raise (AssertionError(result), msg)
        return result

    return run_command


def create_docker_client():
    try:
        if use_environ():
            print("using environment to create docker client")
            c = docker.from_env()
        else:
            c = docker.DockerClient(
                base_url="unix://var/run/docker.sock", version="auto"
            )
        # XXX ?
        c.run = run(c)
        return c
    except DockerException as e:
        print("Unable to connect to a docker socket")
        raise pytest.UsageError(
            "Could not connect to a running docker socket: %s" % str(e)
        )
