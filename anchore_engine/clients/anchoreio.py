import base64
import copy
import json
import urllib.parse
import abc
import requests

import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.utils import AnchoreException

anchoreio_clients = {}


class InsufficientAccessTierError(Exception):
    pass


class InvalidCredentialsError(Exception):
    def __init__(self, username, target):
        super(InvalidCredentialsError, self).__init__(
            'Invalid credential for user {} for url: {}'.format(username, target))


class IAuthenticatedHTTPClientBase(abc.ABC):
    @abc.abstractmethod
    def execute_request(self, method, url, connect_timeout=None, read_timeout=None, retries=None):
        pass


    @property
    @abc.abstractmethod
    def user(self):
        pass


class Oauth2AuthenticatedClient(IAuthenticatedHTTPClientBase):
    """
    Simple base client type for operations with oauth2, with enhancements for the ancho.re api
    """

    client_config = {
        'max_retries': 3,
        'conn_timeout': 3,
        'read_timeout': 60,
        'client_info_url': None,
        'token_url': None,
        'client_info': {},
        'user_info': {},
        'token_info': {}
    }

    def _map_error_to_exception(self, exc, username, url=None):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError(
                'Access denied due to insufficient permissions for user: {}'.format(username))
        else:
            raise Exception('Feed operation failed for user: {}. Msg: {}. Response: {}'.format(self.user, exc.response, exc.response.text))

    def __init__(self, token_url, client_url, username, password, token=None, connect_timeout=None, read_timeout=None, retries=None):
        self.token_url = token_url
        self.client_url = client_url
        self._user = username
        self.password = password
        self.token = token

        self.auth_config = copy.copy(self.client_config)
        self.auth_config['username'] = self.user
        self.auth_config['password'] = self.password
        self.auth_config['token_url'] = self.token_url
        self.auth_config['client_info_url'] = self.client_url
        if connect_timeout:
            self.auth_config['conn_timeout'] = connect_timeout
        if read_timeout:
            self.auth_config['read_timeout'] = read_timeout

        if retries:
            self.auth_config['max_retries'] = retries

        try:
            self.user_info = self._get_current_user_info()
        except requests.HTTPError as e:
            raise self._map_error_to_exception(e, username=self.user, url=self.token_url)

    @property
    def user(self):
        return self._user

    def _get_current_user_info(self):
        """
        Return the metadata about the current user as supplied by the anchore.io service. Includes permissions and tier access.

        :return: Dict of user metadata
        """
        user_url = '{}/{}'.format(self.auth_config['client_info_url'], self.auth_config['username'])
        user_timeout = 60
        retries = 3
        result = requests.get(user_url, headers={'x-anchore-password': self.auth_config['password']})
        if result.status_code == 200:
            user_data = result.json()
        else:
            raise result.raise_for_status()
        return user_data

    def _auth_invalidate(self):
        if 'client_info' in self.auth_config:
            self.auth_config['client_info'] = {}

        if 'token_info' in self.auth_config:
            self.auth_config['token_info'] = {}

        if 'user_info' in self.auth_config:
            self.auth_config['user_info'] = {}

    def _auth_refresh(self, forcerefresh=False):
        ret = {'success': False, 'text': "", 'status_code': 0}
        if not self.auth_config:
            ret['text'] = json.dumps("no self.auth_config token given as input")
            return (False, ret)

        new_anchore_auth = {}
        new_anchore_auth.update(self.auth_config)

        username = self.auth_config['username']
        password = self.auth_config['password']
        url_username = urllib.parse.quote_plus(username)
        url_password = urllib.parse.quote_plus(password)
        client_info_url = self.auth_config['client_info_url']
        token_url = self.auth_config['token_url']
        client_info = self.auth_config['client_info']
        token_info = self.auth_config['token_info']
        user_info = self.auth_config['user_info']
        conn_timeout = int(self.auth_config['conn_timeout'])
        read_timeout = int(self.auth_config['read_timeout'])
        timeout_tuple = (conn_timeout, read_timeout)

        if not client_info:
            # get client info
            url = '{}/{}'.format(client_info_url, username)

            headers = {'x-anchore-password': password}
            try:
                r = requests.get(url, headers=headers, timeout=timeout_tuple)
            except:
                # print "request timed out"
                ret['text'] = json.dumps(
                    "connection timed out: increase self.auth_config_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code

            if r.status_code == 200:
                new_anchore_auth['client_info'] = r.json()['clients'][0]
                client_info = new_anchore_auth['client_info']
                ret['success'] = True
            else:
                r.raise_for_status()

        else:
            pass
            # print "skipping client_info get"

        b64bearertok = str(base64.b64encode('{}:{}'.format(client_info['client_id'], client_info['client_secret']).encode('utf-8')), 'utf-8')

        if not token_info:
            # get a token set
            payload = "grant_type=password&username=" + url_username + "&password=" + url_password
            headers = {
                'content-type': "application/x-www-form-urlencoded",
                'authorization': "Basic " + b64bearertok,
                'cache-control': "no-cache",
            }
            try:
                r = requests.post(token_url, headers=headers, data=payload, timeout=timeout_tuple)
            except:
                # print "request timed out"
                ret['text'] = json.dumps(
                    "connection timed out: increase self.auth_config_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code
            if r.status_code == 200:
                new_anchore_auth['token_info'] = r.json() #json.loads(str(r.text, 'utf-8'))
                ret['success'] = True
            else:
                r.raise_for_status()

        elif forcerefresh:
            # print "refreshening"
            payload = "grant_type=refresh_token&refresh_token=" + token_info['refreshToken']
            headers = {
                'content-type': "application/x-www-form-urlencoded",
                'authorization': "Basic " + b64bearertok,
                'cache-control': "no-cache",
            }
            try:
                r = requests.post(token_url, headers=headers, data=payload, timeout=timeout_tuple)
            except:
                # print "request timed out"
                ret['text'] = json.dumps(
                    "connection timed out: increase self.auth_config_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code
            if r.status_code == 200:
                new_anchore_auth['token_info'] = r.json() #json.loads(str(r.text, 'utf-8'))
                ret['success'] = True
            else:
                r.raise_for_status()

        else:
            pass
            # print "skipping token_info get"

        if not user_info or forcerefresh:
            # Update the cached local user data
            new_user_info = self._get_current_user_info()
            new_anchore_auth['user_info'] = new_user_info

        if self.auth_config != new_anchore_auth:
            self.auth_config.update(new_anchore_auth)
        else:
            pass
            # print "skipping save"

        return (True, ret)

    def execute_request(self, method, url, connect_timeout=None, read_timeout=None, retries=None):
        """
        Operate with the given requests.method (eg. requests.get) on a url using the authentication token

        :param url:
        :param timeout:
        :param retries:
        :return:
        """

        # make a request
        if not connect_timeout:
            conn_timeout = int(self.auth_config['conn_timeout'])
        if not read_timeout:
            read_timeout = int(self.auth_config['read_timeout'])

        if not retries:
            retries = int(self.auth_config['max_retries'])

        retries = int(retries)

        ret = {'status_code': 1, 'text': '', 'success': False}

        success = False
        count = 0

        conn_timeout = int(conn_timeout)
        read_timeout = int(read_timeout)

        while not success and count < retries:
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                rc, record = self._auth_refresh(forcerefresh=False)
                if not rc:
                    # print "cannot get valid auth token"
                    ret['text'] = record['text']
                    return (ret)
                else:
                    token_info = self.auth_config['token_info']
                    accessToken = token_info['accessToken']
                    headers = {"Authorization": "Bearer " + accessToken, "Cache-Control": "no-cache"}

                    logger.debug("making authenticated request to url: " + str(url))
                    r = method(url, headers=headers, timeout=(conn_timeout, read_timeout))
                    logger.debug("\tresponse status_code: " + str(r.status_code))
                    if r.status_code == 401:
                        logger.debug(
                            "Got HTTP 401 on authenticated {}, response body: {}".format(method.__name__, str(r.text)))
                        resp = r.json() #json.loads(str(r.text, 'utf-8'))
                        if 'name' in resp and resp['name'] == 'invalid_token':
                            # print "bad tok - attempting to refresh"
                            rc, record = self._auth_refresh(forcerefresh=True)
                            if not rc:
                                # start over and retry
                                # print "refresh token failed, invalidating tok and starting over"
                                self._auth_invalidate()
                        else:
                            r.raise_for_status()

                    elif r.status_code == 200:
                        success = True
                        ret['success'] = True
                    elif r.status_code in [403, 404]:
                        r.raise_for_status()

                    ret['status_code'] = r.status_code
                    ret['text'] = r.text

            except requests.exceptions.ConnectTimeout as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: timed_out: " + str(err)

            except requests.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._map_error_to_exception(e, username=self.user, url=url)
                    #raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    ret['text'] = 'server error: ' + str(e)
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: " + str(err)

        return ret

    def authenticated_get(self, url, connect_timeout=None, read_timeout=None, retries=None):
        return self.execute_request(requests.get, url, connect_timeout, read_timeout, retries)


class HTTPBasicAuthClient(IAuthenticatedHTTPClientBase):
    """
    Simple base client type for operations with no auth needed
    """

    client_config = {
        'max_retries': 3,
        'conn_timeout': 3,
        'read_timeout': 60
    }

    def __init__(self, username, password, connect_timeout=None, read_timeout=None, retries=None):
        self.auth_config = copy.copy(self.client_config)
        self._user = username
        self.password = password
        self.retries = retries

        if connect_timeout:
            self.auth_config['conn_timeout'] = connect_timeout
        if read_timeout:
            self.auth_config['read_timeout'] = read_timeout
        if retries:
            self.auth_config['max_retries'] = retries

    @property
    def user(self):
        return self._user

    def _map_error_to_exception(self, exc, username, url=None):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError(
                'Access denied due to insufficient permissions for user: {}'.format(username))
        else:
            raise Exception(
                'Feed operation failed for user: {}. Msg: {}. Response: {}'.format(self.user, exc.response,
                                                                                   exc.response.body))

    def authenticated_get(self, url, connect_timeout=None, read_timeout=None, retries=None):
        return self.execute_request(requests.get, url, connect_timeout, read_timeout, retries)

    def execute_request(self, method, url, connect_timeout=None, read_timeout=None, retries=None):
        """
        Execute an HTTP request with auth params and the specified timeout overrides

        :param method: a callable for the http method to execute (e.g. requests.get, requests.put, ...)
        :param url:
        :param timeout:
        :param retries:
        :return:
        """

        # make a request
        if not connect_timeout:
            conn_timeout = int(self.auth_config['conn_timeout'])
        if not read_timeout:
            read_timeout = int(self.auth_config['read_timeout'])

        if not retries:
            retries = int(self.auth_config['max_retries'])

        retries = int(retries)

        ret = {'status_code': 1, 'text': '', 'success': False}

        success = False
        count = 0

        conn_timeout = int(conn_timeout)
        read_timeout = int(read_timeout)

        while not success and count < retries:
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                if False:
                    pass
                else:
                    auth = (self.user, self.password)
                    logger.debug("making authenticated request (user=" + str(self.user) + ") to url: " + str(url))
                    r = method(url, auth=auth, timeout=(conn_timeout, read_timeout))
                    logger.debug("\tresponse status_code: " + str(r.status_code))
                    if r.status_code == 401:
                        logger.debug(
                            "Got HTTP 401 on authenticated {}, response body: {}".format(method.__name__, str(r.text)))
                        r.raise_for_status()
                    elif r.status_code == 200:
                        success = True
                        ret['success'] = True
                    elif r.status_code in [403, 404]:
                        r.raise_for_status()

                    ret['status_code'] = r.status_code
                    ret['text'] = r.text

            except requests.exceptions.ConnectTimeout as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: timed_out: " + str(err)
                # return(ret)

            except requests.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._map_error_to_exception(e, username=self.user, url=url)
                    #raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    ret['text'] = 'server error: ' + str(e)
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: " + str(err)

        return (ret)


def get_anchoreio_client(user, pw):
    global anchoreio_clients

    if user in anchoreio_clients:
        if pw == anchoreio_clients[user].get('pw', None) and anchoreio_clients[user].get('client', None):
            return(anchoreio_clients[user]['client'])
        else:
            del(anchoreio_clients[user]['client'])
            anchoreio_clients[user] = {}

    # make a new client
    localconfig = anchore_engine.configuration.localconfig.get_config()

    anchoreio_clients[user] = {}
    try:
        anchoreio_clients[user]['pw'] = pw
        anchoreio_clients[user]['client'] = Oauth2AuthenticatedClient(localconfig.get('feeds', {}).get('token_url'), localconfig.get('feeds', {}).get('client_url'), user, pw, connect_timeout=localconfig.get('connection_timeout_seconds', None), read_timeout=localconfig.get('read_timeout_seconds', None))
    except Exception as err:
        anchoreio_clients.pop(user, None)
        raise AnchoreIOClientError(cause=err)

    return(anchoreio_clients[user]['client'])


class AnchoreIOClientError(AnchoreException):
    def __init__(self, cause, msg='Error initializing anchore.io client with configured credentials'):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)

    def __str__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)
