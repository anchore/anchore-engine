import requests
import requests.exceptions
import base64
import json
import urllib
import copy
import datetime

from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.clients.feeds import Feed, FeedGroup, FeedGroupList, FeedList, IFeedClient, GroupData

# import logging
# logging.basicConfig(level=logging.DEBUG)
# logger = logging.getLogger()

#SINCE_DATE_FORMAT = '%Y-%m-%dT%H:%M' # Minute-level granularity for the since parameter only

class InsufficientAccessTierError(StandardError):
    pass


class InvalidCredentialsError(StandardError):
    def __init__(self, username, target):
        super(InvalidCredentialsError, self).__init__('Invalid credential for user {} for url: {}'.format(username, target))


class BasicAuthClient(object):
    """
    Simple base client type for operations with no auth needed
    """

    client_config = {
        'max_retries': 3,
        'conn_timeout': 3,
        'read_timeout': 60
    }    

    def __init__(self, token_url, client_url, username, password, token=None, connect_timeout=None, read_timeout=None, retries=None):
        self.anchore_auth = copy.copy(self.client_config)
        self.user = username
        self.password = password

        if connect_timeout:
            self.anchore_auth['conn_timeout'] = connect_timeout
        if read_timeout:
            self.anchore_auth['read_timeout'] = read_timeout

    def authenticated_get(self, url, connect_timeout=None, read_timeout=None, retries=None):
        """
        GET a url using the authentication token

        :param url:
        :param timeout:
        :param retries:
        :return:
        """

        # make a request
        if not connect_timeout:
            conn_timeout = int(self.anchore_auth['conn_timeout'])
        if not read_timeout:
            read_timeout = int(self.anchore_auth['read_timeout'])

        if not retries:
            retries = int(self.anchore_auth['max_retries'])

        retries = int(retries)

        ret = {'status_code': 1, 'text': '', 'success': False}

        success = False
        count = 0

        conn_timeout = int(conn_timeout)
        read_timeout = int(read_timeout)

        while (not success and count < retries):
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                if False:
                    pass
                else:
                    auth = (self.user, self.password)
                    logger.debug("making authenticated request (user="+str(self.user)+") to url: " + str(url))
                    r = requests.get(url, auth=auth, timeout=(conn_timeout, read_timeout))
                    logger.debug("\tresponse status_code: " + str(r.status_code))
                    if r.status_code == 401:
                        logger.debug("Got HTTP 401 on authenticated GET, response body: " + str(r.text))
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
                    raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    ret['text'] = 'server error: ' + str(e)
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: " + str(err)

        return (ret)


class Oauth2AuthenticatedClient(object):
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

    def __init__(self, token_url, client_url, username, password, token=None, connect_timeout=None, read_timeout=None, retries=None):
        self.token_url = token_url
        self.client_url = client_url
        self.user = username
        self.password = password
        self.token = token

        self.anchore_auth = copy.copy(self.client_config)
        self.anchore_auth['username'] = self.user
        self.anchore_auth['password'] = self.password
        self.anchore_auth['token_url'] = self.token_url
        self.anchore_auth['client_info_url'] = self.client_url
        if connect_timeout:
            self.anchore_auth['conn_timeout'] = connect_timeout
        if read_timeout:
            self.anchore_auth['read_timeout'] = read_timeout

        self.user_info = self._get_current_user_info()

    def _get_current_user_info(self):
        """
        Return the metadata about the current user as supplied by the anchore.io service. Includes permissions and tier access.

        :return: Dict of user metadata
        """
        user_url = self.anchore_auth['client_info_url'] + '/' + self.anchore_auth['username']
        user_timeout = 60
        retries = 3
        result = requests.get(user_url, headers={'x-anchore-password': self.anchore_auth['password']})
        if result.status_code == 200:
            user_data = json.loads(result.content)
        else:
            raise result.raise_for_status()
        return user_data

    def _auth_invalidate(self):
        if 'client_info' in self.anchore_auth:
            self.anchore_auth['client_info'] = {}

        if 'token_info' in self.anchore_auth:
            self.anchore_auth['token_info'] = {}

        if 'user_info' in self.anchore_auth:
            self.anchore_auth['user_info'] = {}


    def _auth_refresh(self, forcerefresh=False):
        ret = {'success': False, 'text': "", 'status_code': 0}
        if not self.anchore_auth:
            ret['text'] = json.dumps("no self.anchore_auth token given as input")
            return (False, ret)

        new_anchore_auth = {}
        new_anchore_auth.update(self.anchore_auth)

        username = self.anchore_auth['username']
        password = self.anchore_auth['password']
        url_username = urllib.quote_plus(username)
        url_password = urllib.quote_plus(password)
        client_info_url = self.anchore_auth['client_info_url']
        token_url = self.anchore_auth['token_url']
        client_info = self.anchore_auth['client_info']
        token_info = self.anchore_auth['token_info']
        user_info = self.anchore_auth['user_info']
        conn_timeout = int(self.anchore_auth['conn_timeout'])
        read_timeout = int(self.anchore_auth['read_timeout'])
        timeout_tuple = (conn_timeout, read_timeout)

        if not client_info:
            # get client info
            url = client_info_url + "/" + username
            headers = {'x-anchore-password': password}
            try:
                r = requests.get(url, headers=headers, timeout=timeout_tuple)
            except:
                # print "request timed out"
                ret['text'] = json.dumps("connection timed out: increase self.anchore_auth_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code

            if r.status_code == 200:
                new_anchore_auth['client_info'] = json.loads(r.text)['clients'][0]
                client_info = new_anchore_auth['client_info']
                ret['success'] = True
            else:
                r.raise_for_status()

        else:
            pass
            # print "skipping client_info get"

        b64bearertok = base64.b64encode(client_info['client_id'] + ":" + client_info['client_secret'])

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
                ret['text'] = json.dumps("connection timed out: increase self.anchore_auth_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code
            if r.status_code == 200:
                new_anchore_auth['token_info'] = json.loads(r.text)
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
                ret['text'] = json.dumps("connection timed out: increase self.anchore_auth_conn_timeout higher or try again")
                return (False, ret)

            ret['text'] = r.text
            ret['status_code'] = r.status_code
            if r.status_code == 200:
                new_anchore_auth['token_info'] = json.loads(r.text)
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

        if self.anchore_auth != new_anchore_auth:
            self.anchore_auth.update(new_anchore_auth)
        else:
            pass
            # print "skipping save"

        return (True, ret)

    def authenticated_get(self, url, connect_timeout=None, read_timeout=None, retries=None):
        """
        GET a url using the authentication token

        :param url:
        :param timeout:
        :param retries:
        :return:
        """

        # make a request
        if not connect_timeout:
            conn_timeout = int(self.anchore_auth['conn_timeout'])
        if not read_timeout:
            read_timeout = int(self.anchore_auth['read_timeout'])

        if not retries:
            retries = int(self.anchore_auth['max_retries'])

        retries = int(retries)

        ret = {'status_code': 1, 'text': '', 'success': False}

        success = False
        count = 0

        conn_timeout = int(conn_timeout)
        read_timeout = int(read_timeout)

        while (not success and count < retries):
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                rc, record = self._auth_refresh(forcerefresh=False)
                if not rc:
                    # print "cannot get valid auth token"
                    ret['text'] = record['text']
                    return (ret)
                else:
                    token_info = self.anchore_auth['token_info']
                    accessToken = token_info['accessToken']
                    headers = {"Authorization": "Bearer " + accessToken, "Cache-Control": "no-cache"}

                    logger.debug("making authenticated request to url: " + str(url))
                    r = requests.get(url, headers=headers, timeout=(conn_timeout, read_timeout))
                    logger.debug("\tresponse status_code: " + str(r.status_code))
                    if r.status_code == 401:
                        logger.debug("Got HTTP 401 on authenticated GET, response body: " + str(r.text))
                        resp = json.loads(r.text)
                        if 'name' in resp and resp['name'] == 'invalid_token':
                            # print "bad tok - attempting to refresh"
                            rc, record = self._auth_refresh(forcerefresh=True)
                            if not rc:
                                # start over and retry
                                # print "refresh token failed, invalidating tok and starting over"
                                self._auth_invalidate()
                        else:
                            r.raise_for_status()
                            # success = True
                            # ret['success'] = False
                            # ret['err_msg'] = 'not authorized'

                    elif r.status_code == 200:
                        success = True
                        ret['success'] = True
                    elif r.status_code in [403, 404]:
                        r.raise_for_status()
                    # elif r.status_code == 404:
                    #     success = True
                    #     ret['success'] = False
                    # elif r.status_code == 403:
                    #     success = True
                    #     ret['success'] = False
                    #     ret['err_msg'] = 'Access denied, check your access tier'

                    ret['status_code'] = r.status_code
                    ret['text'] = r.text

            except requests.exceptions.ConnectTimeout as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: timed_out: " + str(err)
                # return(ret)

            except requests.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    ret['text'] = 'server error: ' + str(e)
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                ret['text'] = "server error: " + str(err)

        return (ret)

class FeedClientBase(IFeedClient):
    def _map_error_to_exception(self, exc, username):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, self.token_url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError('Access denied due to insufficient permissions for user: {}'.format(username))
        else:
            raise Exception(
                'Feed operation failed for user: {}. Msg: {}. Response: {}'.format(self.user, exc.response, exc.response.body))

    def list_feeds(self, next_token=None):
        base_url = self.feed_url
        url = base_url
        feeds = None
        try:
            record = self.authenticated_get(url, retries=self.client_config['max_retries'])
            if record['success']:
                data = json.loads(record['text'])
                if data and 'feeds' in data:
                    feeds = [Feed(name=x.get('name'), description=x.get('description'), access_tier=x.get('access_tier')) for x in data['feeds']]
                    if 'next_token' in data and data['next_token']:
                        next_token = data['next_token']
                    else:
                        next_token=None
                return FeedList(next_token=next_token, feeds=feeds)
            else:
                raise Exception(
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'), record.get('text')))
        except requests.HTTPError as e:
            raise self._map_error_to_exception(e, self.user)

    def list_feed_groups(self, feed, next_token=None):
        base_url = self.group_url.format(feed=feed)
        url = base_url + (('?next_token=' + next_token) if next_token else '')
        try:
            record = self.authenticated_get(url, retries=self.client_config['max_retries'])
            if record['success']:
                data = json.loads(record['text'])
                if 'groups' in data:
                    groups = [FeedGroup(feed=feed, name=x.get('name'), description=x.get('description'), access_tier=x.get('access_tier')) for x in data['groups']]
                else:
                    groups = None
                if 'next_token' in data and data['next_token']:
                    next_token = data['next_token']
                else:
                    next_token = None

                return FeedGroupList(next_token=next_token, groups=groups)
            else:
                raise Exception(
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'), record.get('text')))
        except requests.HTTPError as e:
            raise self._map_error_to_exception(e, self.user)

    def get_feed_group_data(self, feed, group, since=None, next_token=None):
        if since and not isinstance(since, datetime.datetime):
            raise TypeError('since should be a datetime object')

        baseurl = self.group_data_url.format(feed=feed, group=group)
        if since:
            baseurl += "?since={}".format(since.isoformat())
            if next_token:
                url = baseurl + '&next_token={}'.format(next_token)
            else:
                url = baseurl
        elif next_token:
            url = baseurl + '?next_token={}'.format(next_token)
        else:
            url = baseurl

        group_data = None

        logger.debug("data group url: " + str(url))
        try:
            record = self.authenticated_get(url, retries=self.client_config['max_retries'])
            if record['success']:
                data = json.loads(record['text'])
                if 'data' in data:
                    group_data = data['data']
                if 'next_token' in data and data['next_token']:
                    next_token = data['next_token']
                else:
                    next_token = None
                return GroupData(data=group_data, next_token=next_token, since=since)
            else:
                raise Exception(
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'), record.get('text')))
        except requests.HTTPError as e:
            raise self._map_error_to_exception(e, self.user)

class AnchoreIOFeedClient(FeedClientBase, Oauth2AuthenticatedClient):
    """
    Client for making requests against the anchore.io feed service using authentication or the anonymous user.
    Provides a single-request abstraction, so caller must handle the chunking of data etc as desired.

    """
    def __init__(self, feed_url, token_url, client_url, username, password, connect_timeout=None, read_timeout=None):
        try:
            super(AnchoreIOFeedClient, self).__init__(token_url, client_url, username, password, connect_timeout, read_timeout)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                raise InvalidCredentialsError(self.user, token_url)
            else:
                raise e

        self.feed_url = feed_url
        self.group_url = feed_url + '/{feed}'
        self.group_data_url = self.group_url + '/{group}'

class FeedServiceFeedClient(FeedClientBase, BasicAuthClient):
    """
    Client for making requests against the anchore.io feed service using authentication or the anonymous user.
    Provides a single-request abstraction, so caller must handle the chunking of data etc as desired.

    """
    def __init__(self, feed_url, token_url, client_url, username, password, connect_timeout=None, read_timeout=None):
        try:
            super(FeedServiceFeedClient, self).__init__(token_url, client_url, username, password, connect_timeout, read_timeout)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                raise InvalidCredentialsError(self.user, token_url)
            else:
                raise e

        self.feed_url = feed_url
        self.group_url = feed_url + '/{feed}'
        self.group_data_url = self.group_url + '/{group}'

def get_client(feeds_url=None, token_url=None, client_url=None, user=tuple(), conn_timeout=None, read_timeout=None):
    """
    Returns a configured client based on the local config. Reads configuration from the loaded system configuration.

    Uses the admin user's credentials for the feed service if they are available in the external_service_auths/anchoreio/anchorecli/auth json path of the config file. If no specific user credentials are found then the anonymous user credentials are used.

    :return: initialize AnchoreIOFeedClient
    """

    logger.debug('Initializing a feeds client')
    logger.debug("init values: " + str([feeds_url, token_url, client_url, user, conn_timeout, read_timeout]))
    if not (feeds_url and token_url and client_url and user and conn_timeout and read_timeout):
        conf = localconfig.get_config()
        if not conf:
            logger.error('No configuration available. Cannot initialize feed client')
            raise ValueError('None for local config')

    if not conn_timeout:
        conn_timeout = conf.get('feeds', {}).get('connection_timeout_seconds')

    if not read_timeout:
        read_timeout = conf.get('feeds', {}).get('read_timeout_seconds')

    if not feeds_url:
        feeds_url = conf.get('feeds', {}).get('url')

    if not token_url:
        token_url = conf.get('feeds', {}).get('token_url')

    if not client_url:
        client_url = conf.get('feeds', {}).get('client_url')

    if not user:
        try:
            admin_usr = conf.get('credentials', {}).get('users', {}).get('admin', {})\
                .get('external_service_auths', {}).get('anchoreio', {}).get('anchorecli',{}).get('auth')
            if admin_usr:
                user, password = admin_usr.split(':')
        except AttributeError:
            # Something isn't found or was set to None.
            pass
    else:
        user, password = user[0], user[1]

    if not user:
        user = conf.get('feeds', {}).get('anonymous_user_username')
        password = conf.get('feeds', {}).get('anonymous_user_password')

    logger.debug("using values: " + str([feeds_url, token_url, client_url, user, conn_timeout, read_timeout]))
    # TODO need a better way to select which client to return, here
    if token_url and client_url:
        return AnchoreIOFeedClient(feed_url=feeds_url, token_url=token_url, client_url=client_url, username=user, password=password, connect_timeout=conn_timeout, read_timeout=read_timeout)
    else:
        return FeedServiceFeedClient(feed_url=feeds_url, token_url=token_url, client_url=client_url, username=user, password=password, connect_timeout=conn_timeout, read_timeout=read_timeout)


