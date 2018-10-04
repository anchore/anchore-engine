#!/usr/bin/env python3
import requests
import uuid
import time

# Functional tests for user management flows for the api

# User and endpoint for most requests
base_url = 'http://localhost/v1'
base_auth = ('admin', 'foobar')


class SimpleClient(object):
    def __init__(self, username, password, base_url=None):
        self.auth = (username, password)
        self.base_url = base_url

    def _dispatch(self, method, path, body=None, params=None, auth=None):
        if not auth:
            auth = self.auth

        url = '/'.join([self.base_url, path])
        print('Dispatching: method={}, url={}, body={}, params={}'.format(method.__name__, url, body, params))
        resp = method(url=url, json=body, params=params, auth=auth)
        print('Got response: Code={}, Content={}'.format(resp.status_code, resp.content))
        return resp

    def create_user(self, account_name, user_name, password):
        path = 'accounts/{account}/users'.format(account=account_name)
        body = {
            'username': user_name,
            'password': password
        }
        return self._dispatch(requests.post, path, body=body)

    def delete_user(self, account_name, user_name):
        path = 'accounts/{account}/users/{user}'.format(account=account_name, user=user_name)
        return self._dispatch(requests.delete, path)

    def get_user(self, account_name, user_name):
        path = 'accounts/{account}/users/{user}'.format(account=account_name, user=user_name)
        return self._dispatch(requests.get, path)

    def add_credential(self, account_name, user_name, password):
        path = 'accounts/{account}/users/{user}/credentials'.format(account=account_name, user=user_name)
        body = {
            'type': 'password',
            'value': password
        }
        return self._dispatch(requests.post, path, body=body)

    def get_credential(self, account_name, user_name):
        path = 'accounts/{account}/users/{user}/credentials'.format(account=account_name, user=user_name)
        return self._dispatch(requests.get, path)

    def delete_credential(self, account_name, user_name, cred_type):
        path = 'accounts/{account}/users/{user}/credentials'.format(account=account_name, user=user_name)
        return self._dispatch(requests.delete, path, params={'credential_type': cred_type})

    def create_account(self, account_name, account_type):
        path = 'accounts'
        body = {
            'name': account_name,
            'email': account_name + "@account",
            'type': account_type
        }

        return self._dispatch(requests.post, path, body=body)

    def get_account(self, account_name):
        path = 'accounts/{account}'.format(account=account_name)
        return self._dispatch(requests.get, path)

    def delete_account(self, account_name):
        path = 'accounts/{account}'.format(account=account_name)
        return self._dispatch(requests.delete, path)

    def list_accounts(self):
        path = 'accounts'
        return self._dispatch(requests.get, path)

    def get_users(self, account_name):
        path = 'accounts/{account}/users'.format(account=account_name)
        return self._dispatch(requests.get, path)

    def activate_account(self, account_name):
        path = 'accounts/{account}/activate'.format(account=account_name)
        return self._dispatch(requests.post, path)

    def deactivate_account(self, account_name):
        path = 'accounts/{account}/deactivate'.format(account=account_name)
        return self._dispatch(requests.post, path)

    def user(self):
        path = 'user'
        return self._dispatch(requests.get, path)

    def account(self):
        path = 'account'
        return self._dispatch(requests.get, path)


def basic_user_test(data_matrix_tuple):
    client = SimpleClient(username=base_auth[0], password=base_auth[1], base_url=base_url)

    for entry in data_matrix_tuple:
        account = entry['account']

        print('Creating new account: {}'.format(account['name']))
        client.create_account(account['name'], account['type'])

        for username, password in account['users']:
            print('Creating new user: {}:{}'.format(username, password))
            resp = client.create_user(account['name'], username, password)
            print('Response: {}'.format(resp))

            print('Testing auth for new user')
            resp = client.query_user(username, password)
            print('Check response: {}'.format(resp))


def assert_ok(resp):
    if not resp.status_code in [200, 204]:
        raise AssertionError('{} not in 200, 204'.format(resp.status_code))
    else:
        print('Got expected 200/204')


def assert_not_found(resp):
    if not resp.status_code == 404:
        raise AssertionError('{} != 404'.format(resp.status_code))
    else:
        print('Got exepcted 404')


def assert_bad_request(resp):
    if not resp.status_code == 400:
        raise AssertionError('{} != 400'.format(resp.status_code))
    else:
        print('Got expected 400')


def assert_denied(resp):
    if not resp.status_code == 403:
        raise AssertionError('{} != 403'.format(resp.status_code))
    else:
        print('Got expected 403')


def assert_unauthorized(resp):
    if not resp.status_code == 401:
        raise AssertionError('{} != 401'.format(resp.status_code))
    else:
        print('Got expected 401')


def test_account_lifecycle(account_name, account_type):
    """
    Create, Get, Delete

    :param accountname:
    :param account_type:
    :return:

    """

    username = uuid.uuid4().hex
    print('Using user: {}'.format(username))

    client = SimpleClient(username=base_auth[0], password=base_auth[1], base_url=base_url)
    assert_ok(client.create_account(account_name, account_type))
    assert_ok(client.get_account(account_name))

    assert_ok(client.create_user(account_name, username, 'testpass'))
    assert_ok(client.get_user(account_name, username))

    assert_ok(client.add_credential(account_name, username, 'newpass'))

    user_client = SimpleClient(username=username, password='newpass', base_url=base_url)
    assert_ok(user_client.user())
    assert_ok(user_client.account())

    assert_denied(user_client.list_accounts())
    assert_denied(user_client.get_account(account_name))
    assert_denied(user_client.get_user('admin', 'admin'))
    assert_denied(user_client.get_user(account_name, username))

    assert_ok(client.deactivate_account(account_name))
    print('Sleeping for cache flush')
    time.sleep(6)
    assert_ok(client.get_account(account_name))
    assert_unauthorized(user_client.user())
    assert_ok(client.activate_account(account_name))

    print('Sleeping for cache flush')
    time.sleep(6)
    assert_ok(user_client.user())

    client.delete_credential(account_name, username, cred_type='password')
    print('Sleeping for cache flush')
    time.sleep(6)


    assert_unauthorized(user_client.user())
    client.add_credential(account_name, username, 'newpass')

    print('Sleeping for cache flush')
    time.sleep(6)

    assert_ok(user_client.user())

    assert_ok(client.delete_user(account_name, username))
    assert_not_found(client.get_user(account_name, username))

    assert_ok(client.delete_account(account_name))
    assert_not_found(client.get_account(account_name))


def test_duplicate_account_create(account_name, account_type):
    client = SimpleClient(username=base_auth[0], password=base_auth[1], base_url=base_url)
    assert_ok(client.create_account(account_name, account_type))
    assert_bad_request(client.create_account(account_name, account_type))
    assert_ok(client.delete_account(account_name))
    assert_not_found(client.get_account(account_name))
    assert_not_found(client.delete_account(account_name))


if __name__ == '__main__':

    test_account = uuid.uuid4().hex
    print('Testing basic account lifecycle with account: {}'.format(test_account))
    test_account_lifecycle(test_account, 'user')
