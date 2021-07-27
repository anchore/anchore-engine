import os
import time
import uuid
from distutils.version import LooseVersion

from . import *

# Functional tests for user management flows for the api
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

    def create_user(self, account_name, user_name, password):
        path = "accounts/{account}/users".format(account=account_name)
        body = {"username": user_name, "password": password}
        return self._dispatch(requests.post, path, body=body)

    def delete_user(self, account_name, user_name):
        path = "accounts/{account}/users/{user}".format(
            account=account_name, user=user_name
        )
        return self._dispatch(requests.delete, path)

    def get_user(self, account_name, user_name):
        path = "accounts/{account}/users/{user}".format(
            account=account_name, user=user_name
        )
        return self._dispatch(requests.get, path)

    def add_credential(self, account_name, user_name, password):
        path = "accounts/{account}/users/{user}/credentials".format(
            account=account_name, user=user_name
        )
        body = {"type": "password", "value": password}
        return self._dispatch(requests.post, path, body=body)

    def get_credential(self, account_name, user_name):
        path = "accounts/{account}/users/{user}/credentials".format(
            account=account_name, user=user_name
        )
        return self._dispatch(requests.get, path)

    def delete_credential(self, account_name, user_name, cred_type):
        path = "accounts/{account}/users/{user}/credentials".format(
            account=account_name, user=user_name
        )
        return self._dispatch(
            requests.delete, path, params={"credential_type": cred_type}
        )

    def create_account(self, account_name, account_type):
        path = "accounts"
        body = {"name": account_name, "email": account_name + "@testaccount.com"}

        return self._dispatch(requests.post, path, body=body)

    def get_account(self, account_name):
        path = "accounts/{account}".format(account=account_name)
        return self._dispatch(requests.get, path)

    def delete_account(self, account_name):
        path = "accounts/{account}".format(account=account_name)
        return self._dispatch(requests.delete, path)

    def list_accounts(self):
        path = "accounts"
        return self._dispatch(requests.get, path)

    def get_users(self, account_name):
        path = "accounts/{account}/users".format(account=account_name)
        return self._dispatch(requests.get, path)

    def activate_account(self, account_name):
        path = "accounts/{account}/state".format(account=account_name)
        return self._dispatch(requests.put, path, body={"state": "enabled"})

    def deactivate_account(self, account_name):
        path = "accounts/{account}/state".format(account=account_name)
        return self._dispatch(requests.put, path, body={"state": "disabled"})

    def user(self):
        path = "user"
        return self._dispatch(requests.get, path)

    def account(self):
        path = "account"
        return self._dispatch(requests.get, path)


def basic_user_test(data_matrix_tuple):
    client = SimpleClient(
        username=base_auth[0], password=base_auth[1], base_url=base_url
    )

    for entry in data_matrix_tuple:
        account = entry["account"]

        print("Creating new account: {}".format(account["name"]))
        client.create_account(account["name"], account["type"])

        for username, password in account["users"]:
            print("Creating new user: {}:{}".format(username, password))
            resp = client.create_user(account["name"], username, password)
            print("Response: {}".format(resp))

            print("Testing auth for new user")
            resp = client.query_user(username, password)
            print("Check response: {}".format(resp))


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


def assert_account_state(resp, state_str):
    if resp.status_code != 200:
        raise AssertionError("Error response for state check: {}".format(resp))

    j = resp.json()
    found = j.get("state")
    if found != state_str:
        raise AssertionError(
            "Expected account state: {}, found {}".format(state_str, found)
        )
    else:
        print("Got expected account state: {}".format(found))


runtest = False


def test_engine_version():
    global runtest

    version = get_engine_version(base_auth[0], base_auth[1], base_url=base_url)
    if version:
        if LooseVersion(version) >= LooseVersion("0.3.0"):
            runtest = True


def test_account_lifecycle():
    if runtest:
        account_name = uuid.uuid4().hex
        print("Testing basic account lifecycle with account: {}".format(account_name))
        account_type = "user"

        username = uuid.uuid4().hex
        print("Using user: {}".format(username))

        admin_client = SimpleClient(
            username=base_auth[0], password=base_auth[1], base_url=base_url
        )
        assert_ok(admin_client.create_account(account_name, account_type))
        assert_ok(admin_client.get_account(account_name))

        assert_ok(admin_client.create_user(account_name, username, "testpass"))
        assert_ok(admin_client.get_user(account_name, username))

        assert_ok(admin_client.add_credential(account_name, username, "newpass"))

        user_client = SimpleClient(
            username=username, password="newpass", base_url=base_url
        )
        assert_ok(user_client.user())
        assert_ok(user_client.account())

        assert_denied(user_client.list_accounts())
        assert_ok(user_client.get_account(account_name))
        assert_denied(user_client.get_account("anotheraccount"))
        assert_denied(user_client.get_user("admin", "admin"))
        assert_ok(user_client.get_user(account_name, username))  # can get itself

        assert_ok(admin_client.deactivate_account(account_name))
        print("Sleeping for cache flush")
        time.sleep(6)
        assert_ok(admin_client.get_account(account_name))
        assert_denied(user_client.user())
        assert_ok(admin_client.activate_account(account_name))

        print("Sleeping for cache flush")
        time.sleep(6)
        assert_ok(user_client.user())

        admin_client.delete_credential(account_name, username, cred_type="password")
        print("Sleeping for cache flush")
        time.sleep(6)

        assert_unauthorized(user_client.user())
        admin_client.add_credential(account_name, username, "newpass")

        print("Sleeping for cache flush")
        time.sleep(6)

        assert_ok(user_client.user())

        assert_ok(admin_client.delete_user(account_name, username))
        assert_not_found(admin_client.get_user(account_name, username))

        assert_ok(admin_client.deactivate_account(account_name))
        assert_ok(admin_client.delete_account(account_name))
        assert_account_state(admin_client.get_account(account_name), "deleting")

        for i in range(10):
            time.sleep(10)
            if "deleting" != admin_client.get_account(account_name).json().get(
                "state", None
            ):
                break

        assert_not_found(admin_client.get_account(account_name))


def test_duplicate_account_create():
    if runtest:
        account_name = uuid.uuid4().hex
        print("Testing basic account lifecycle with account: {}".format(account_name))
        account_type = "user"

        username = uuid.uuid4().hex
        print("Using user: {}".format(username))

        admin_client = SimpleClient(
            username=base_auth[0], password=base_auth[1], base_url=base_url
        )
        assert_ok(admin_client.create_account(account_name, account_type))
        assert_bad_request(admin_client.create_account(account_name, account_type))
        assert_ok(admin_client.deactivate_account(account_name))
        assert_ok(admin_client.delete_account(account_name))
        assert_account_state(admin_client.get_account(account_name), "deleting")

        for i in range(10):
            time.sleep(10)
            if "deleting" != admin_client.get_account(account_name).json().get(
                "state", None
            ):
                break

        assert_not_found(admin_client.get_account(account_name))
