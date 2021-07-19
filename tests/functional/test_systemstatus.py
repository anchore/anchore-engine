import os
from distutils.version import LooseVersion

from . import *

# Functional tests for system status as a basic connectivity/anchore-engine up test
anchore_user = os.environ["ANCHORE_CLI_USER"]
anchore_pass = os.environ["ANCHORE_CLI_PASS"]
anchore_url = os.environ["ANCHORE_CLI_URL"]

# User and endpoint for most requests
base_url = anchore_url
base_auth = (anchore_user, anchore_pass)


class SimpleClient(object):
    def __init__(self, username, password, base_url=None):
        self.auth = (username, password)
        self.base_url = base_url

    def _dispatch(self, method, path, body=None, params=None, auth=None):
        if not auth:
            auth = self.auth

        url = "/".join([self.base_url, path])
        print(
            "Dispatching: method={}, url={}, body={}, params={}".format(
                method.__name__, url, body, params
            )
        )
        resp = method(url=url, json=body, params=params, auth=auth)
        print(
            "Got response: Code={}, Content={}".format(resp.status_code, resp.content)
        )
        return resp

    def system_status(self):
        path = "system/"
        return self._dispatch(requests.get, path)


def assert_ok(resp):
    if not resp.status_code in [200, 204]:
        raise AssertionError("{} not in 200, 204".format(resp.status_code))
    else:
        print("Got expected 200/204")


def assert_not_found(resp):
    if not resp.status_code == 404:
        raise AssertionError("{} != 404".format(resp.status_code))
    else:
        print("Got exepcted 404")


def assert_bad_request(resp):
    if not resp.status_code == 400:
        raise AssertionError("{} != 400".format(resp.status_code))
    else:
        print("Got expected 400")


def assert_denied(resp):
    if not resp.status_code == 403:
        raise AssertionError("{} != 403".format(resp.status_code))
    else:
        print("Got expected 403")


def assert_unauthorized(resp):
    if not resp.status_code == 401:
        raise AssertionError("{} != 401".format(resp.status_code))
    else:
        print("Got expected 401")


runtest = False


def test_engine_version():
    global runtest

    version = get_engine_version(base_auth[0], base_auth[1], base_url=base_url)
    if version:
        if LooseVersion(version) > LooseVersion("0.0.0"):
            runtest = True


def test_system_status():
    global runtest

    if runtest:
        print("Testing system status route")
        admin_client = SimpleClient(
            username=base_auth[0], password=base_auth[1], base_url=base_url
        )
        assert_ok(admin_client.system_status())
