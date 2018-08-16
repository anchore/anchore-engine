from collections.__init__ import namedtuple

import requests
import requests.exceptions
import json
import datetime

from anchore_engine.clients.anchoreio import Oauth2AuthenticatedClient, HTTPBasicAuthClient, InsufficientAccessTierError, InvalidCredentialsError
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger


def enable_py_logging():
    import logging
    logging.basicConfig(level=logging.DEBUG)
    return logging.getLogger()


class IFeedClient(object):
    """
    Base interface for a feed source
    """

    def list_feeds(self):
        """
        Get feed listing
        :return: FeedList
        """
        raise NotImplementedError()

    def list_feed_groups(self, feed):
        """
        Get groups for the feed
        :param feed: str name of feed to list
        :return: FeedGroupList
        """
        raise NotImplementedError()

    def get_feed_group_data(self, feed, group, since=None, next_token=None):
        """
        Get group data for the feed group that is newer than the since str. lexicographically
        Data is a list of dictionaries/json objects provided by the feed with no guarantees for uniqueness or ordering.

        :param feed: str name of feed to query
        :param group: str name of group within feed
        :param since: data str prefix, in iso-8601 format. e.g '2017-01-30' or '2017-01-30T12:00'
        :param next_token: token to fetch next chunk of data
        :return: GroupData
        """
        raise NotImplementedError()


class FeedClient(IFeedClient):
    """
    Base client class with no auth
    """

    def __init__(self, endpoint, http_client=None):
        self.http_client = http_client
        self.feed_url = endpoint
        self.group_url = self.feed_url + '/{feed}'
        self.group_data_url = self.group_url + '/{group}'

    def _map_error_to_exception(self, exc, username, url):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError(
                'Access denied due to insufficient permissions for user: {}'.format(username))
        else:
            raise Exception(
                'Feed operation failed for user: {}. Msg: {}. Response: {}'.format(username, exc.response,
                                                                                  exc.response.body))

    def list_feeds(self, next_token=None):
        base_url = self.feed_url
        url = base_url
        feeds = None
        try:
            record = self.http_client.execute_request(requests.get, url)

            if record['success']:
                data = json.loads(record['text'])
                if data and 'feeds' in data:
                    feeds = [
                        Feed(name=x.get('name'), description=x.get('description'), access_tier=x.get('access_tier')) for
                        x in data['feeds']]
                    if 'next_token' in data and data['next_token']:
                        next_token = data['next_token']
                    else:
                        next_token = None
                return FeedList(next_token=next_token, feeds=feeds)
            else:
                raise Exception(
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'), record.get('text')))
        except Exception as e:
            logger.exception('Error executing feed listing: {}'.format(e))
            raise e

    def list_feed_groups(self, feed, next_token=None):
        base_url = self.group_url.format(feed=feed)
        url = base_url + (('?next_token=' + next_token) if next_token else '')
        try:
            record = self.http_client.execute_request(requests.get, url)
            if record['success']:
                data = json.loads(record['text'])
                if 'groups' in data:
                    groups = [FeedGroup(feed=feed, name=x.get('name'), description=x.get('description'),
                                        access_tier=x.get('access_tier')) for x in data['groups']]
                else:
                    groups = None
                if 'next_token' in data and data['next_token']:
                    next_token = data['next_token']
                else:
                    next_token = None

                return FeedGroupList(next_token=next_token, groups=groups)
            else:
                raise Exception(
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'),
                                                                               record.get('text')))
        except Exception as e:
            logger.debug('Error executing feed listing: {}'.format(e))
            raise e

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
            record = self.http_client.execute_request(requests.get, url)
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
                    'Feed list operation failed. Msg: {}. Response: {}'.format(record.get('err_msg'),
                                                                               record.get('text')))
        except Exception as e:
            logger.debug('Error executing feed listing: {}'.format(e))
            raise e


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

    password = None

    if not user:
        try:
            admin_usr = conf.get('credentials', {}).get('users', {}).get('admin', {}) \
                .get('external_service_auths', {}).get('anchoreio', {}).get('anchorecli', {}).get('auth')
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
        http_client = Oauth2AuthenticatedClient(token_url=token_url,
                                                client_url=client_url,
                                                username=user,
                                                password=password,
                                                connect_timeout=conn_timeout,
                                                read_timeout=read_timeout)
    else:
        http_client = HTTPBasicAuthClient(username=user,
                                          password=password,
                                          connect_timeout=conn_timeout,
                                          read_timeout=read_timeout)

    return FeedClient(endpoint=feeds_url, http_client=http_client)


FeedGroup = namedtuple('FeedGroup', ['feed', 'name', 'access_tier', 'description'])
FeedGroupList = namedtuple('FeedList', ['next_token', 'groups'])
Feed = namedtuple('Feed', ['name', 'description', 'access_tier'])
FeedList = namedtuple('FeedList', ['next_token', 'feeds'])
GroupData = namedtuple('GroupData', ['data', 'next_token', 'since'])