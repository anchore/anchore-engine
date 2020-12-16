import abc
import copy

import requests
import requests.exceptions
import json
import datetime
import typing

from io import BytesIO
import ijson

from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_str, ensure_bytes, AnchoreException
from anchore_engine.services.policy_engine.engine.feeds import (
    IFeedSource,
    FeedGroupList,
    FeedList,
    GroupData,
)
from anchore_engine.common.schemas import (
    FeedAPIRecord,
    FeedAPIGroupRecord,
)

FEED_DATA_ITEMS_PATH = "data.item"
FEED_DATA_NEXT_TOKEN_PATH = "next_token"


class FeedServiceClient(IFeedSource):
    """
    Base client class with no auth
    """

    def __init__(self, endpoint, http_client=None):
        if not endpoint:
            raise ValueError("endpoint cannot be None")

        self.http_client = http_client
        self.feed_url = endpoint
        self.group_url = self.feed_url + "/{feed}"
        self.group_data_url = self.group_url + "/{group}"
        self.retry_count = 3

    def _map_error_to_exception(self, exc, username, url):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError(
                "Access denied due to insufficient permissions for user: {}".format(
                    username
                )
            )
        else:
            raise Exception(
                "Feed operation failed for user: {}. Msg: {}. Response: {}".format(
                    username, exc.response, exc.response.body
                )
            )

    def list_feeds(self) -> FeedList:
        more_data = True
        next_token = None
        feed_list = FeedList(feeds=[])

        while more_data:
            url = self.feed_url + (("?next_token=" + next_token) if next_token else "")

            try:
                record = self.http_client.execute_request(
                    requests.get, url, retries=self.retry_count
                )

                if record["success"]:
                    data = json.loads(ensure_str(record["content"]))
                    if data and "feeds" in data:
                        feed_list.feeds.extend(
                            [
                                FeedAPIRecord(
                                    name=x.get("name"),
                                    description=x.get("description"),
                                    access_tier=x.get("access_tier"),
                                )
                                for x in data["feeds"]
                            ]
                        )
                        if "next_token" in data and data["next_token"]:
                            next_token = data["next_token"]
                            more_data = True
                        else:
                            more_data = False
                else:
                    raise Exception(
                        "Feed list operation failed. Msg: {}. Response: {}".format(
                            record.get("err_msg"), record.get("text")
                        )
                    )
            except Exception as e:
                logger.exception("Error executing feed listing: {}".format(e))
                raise e

        return feed_list

    def list_feed_groups(self, feed: str) -> FeedGroupList:
        group_list = FeedGroupList(groups=[])
        more_data = True
        next_token = None

        while more_data:
            url = self.group_url.format(feed=feed) + (
                ("?next_token=" + next_token) if next_token else ""
            )

            try:
                record = self.http_client.execute_request(
                    requests.get, url, retries=self.retry_count
                )
                if record["success"]:
                    data = json.loads(ensure_str(record["content"]))
                    if "groups" in data:
                        group_list.groups.extend(
                            [
                                FeedAPIGroupRecord(
                                    name=x.get("name"),
                                    description=x.get("description"),
                                    access_tier=x.get("access_tier"),
                                )
                                for x in data["groups"]
                            ]
                        )
                    if "next_token" in data and data["next_token"]:
                        next_token = data["next_token"]
                        more_data = True
                    else:
                        more_data = False
                else:
                    raise Exception(
                        "Feed list operation failed. Msg: {}. Response: {}".format(
                            record.get("err_msg"), record.get("text")
                        )
                    )
            except Exception as e:
                logger.debug("Error executing feed listing: {}".format(e))
                raise e

        return group_list

    def get_feed_group_data(
        self,
        feed: str,
        group: str,
        since: datetime.datetime = None,
        next_token: str = None,
    ):
        try:
            record = self.get_raw_feed_group_data(feed, group, since, next_token)
            if record["success"]:
                next_token, group_data, count = self._extract_response_data(
                    record["content"]
                )
                return GroupData(
                    data=group_data,
                    next_token=next_token,
                    since=since,
                    record_count=count,
                )
            else:
                raise Exception(
                    "Feed list operation failed. Msg: {}. Response: {}".format(
                        record.get("err_msg"), record.get("text")
                    )
                )
        except Exception as e:
            logger.debug("Error executing feed data download: {}".format(e))
            raise e

    def get_raw_feed_group_data(
        self,
        feed: str,
        group: str,
        since: datetime.datetime = None,
        next_token: str = None,
    ) -> typing.Tuple:
        if since and not isinstance(since, datetime.datetime):
            raise TypeError("since should be a datetime object")

        baseurl = self.group_data_url.format(feed=feed, group=group)
        if since:
            baseurl += "?since={}".format(since.isoformat())
            if next_token:
                url = baseurl + "&next_token={}".format(next_token)
            else:
                url = baseurl
        elif next_token:
            url = baseurl + "?next_token={}".format(next_token)
        else:
            url = baseurl

        logger.debug("data group url: " + str(url))
        try:
            return self.http_client.execute_request(
                requests.get, url, retries=self.retry_count
            )
        except Exception as e:
            logger.debug("Error executing feed data download: {}".format(e))
            raise e

    def _extract_response_data(self, response_text):
        next_token = None
        sio = BytesIO(response_text)
        count = 0

        # Get the next token
        p = ijson.items(sio, FEED_DATA_NEXT_TOKEN_PATH)
        d = [x for x in p]
        if len(d) == 1:
            next_token = d[0]

        # Be explicit, no empty strings
        if not next_token:
            next_token = None

        # Get the record count
        # Not using the special parser for handling decimals here because this isn't on the return path, just counting records
        sio.seek(0)
        for i in ijson.items(sio, FEED_DATA_ITEMS_PATH):
            count += 1

        logger.debug("Found {} records in data chunk".format(count))
        sio.close()

        return next_token, response_text, count


def get_client(
    feeds_url=None, user=None, conn_timeout=None, read_timeout=None, ssl_verify=None
):
    """
    Returns a configured client based on the local config. Reads configuration from the loaded system configuration.

    Uses the admin user's credentials for the feed service if they are available in the external_service_auths/anchoreio/anchorecli/auth json path of the config file. If no specific user credentials are found then the anonymous user credentials are used.

    :return: initialize AnchoreIOFeedClient
    """

    logger.debug(
        "Initializing a feeds client: url={}, user={}, conn_timeout={}, read_timeout={}".format(
            feeds_url,
            user
            if user is None or type(user) not in [tuple, list] or len(user) == 0
            else (user[0], "***redacted**"),
            conn_timeout,
            read_timeout,
        )
    )

    if not (feeds_url and user and conn_timeout and read_timeout):
        conf = localconfig.get_config()
        if not conf:
            logger.error("No configuration available. Cannot initialize feed client")
            raise ValueError("None for local config")
    else:
        conf = {
            "feeds": {
                "connection_timeout_seconds": conn_timeout,
                "read_timeout_seconds": read_timeout,
                "url": feeds_url,
                "ssl_verify": ssl_verify,
            }
        }

    if not conn_timeout:
        conn_timeout = conf.get("feeds", {}).get("connection_timeout_seconds")

    if not read_timeout:
        read_timeout = conf.get("feeds", {}).get("read_timeout_seconds")

    if not feeds_url:
        feeds_url = conf.get("feeds", {}).get("url")

    if not feeds_url:
        raise ValueError("no feed service url available")

    verify = conf.get("feeds", {}).get("ssl_verify", True)

    password = None

    if not user:
        try:
            admin_usr = (
                conf.get("credentials", {})
                .get("users", {})
                .get("admin", {})
                .get("external_service_auths", {})
                .get("anchoreio", {})
                .get("anchorecli", {})
                .get("auth")
            )
            if admin_usr:
                user, password = admin_usr.split(":")
        except AttributeError:
            # Something isn't found or was set to None.
            pass
    else:
        user, password = user[0], user[1]

    if not user:
        user = conf.get("feeds", {}).get("anonymous_user_username")
        password = conf.get("feeds", {}).get("anonymous_user_password")

    logger.debug("using values: " + str([feeds_url, user, conn_timeout, read_timeout]))

    http_client = HTTPBasicAuthClient(
        username=user,
        password=password,
        connect_timeout=conn_timeout,
        read_timeout=read_timeout,
        verify=verify,
    )

    return FeedServiceClient(endpoint=feeds_url, http_client=http_client)


class InsufficientAccessTierError(Exception):
    pass


class InvalidCredentialsError(Exception):
    def __init__(self, username, target):
        super(InvalidCredentialsError, self).__init__(
            "Invalid credential for user {} for url: {}".format(username, target)
        )


class IAuthenticatedHTTPClientBase(abc.ABC):
    @abc.abstractmethod
    def execute_request(
        self, method, url, connect_timeout=None, read_timeout=None, retries=None
    ):
        pass

    @property
    @abc.abstractmethod
    def user(self):
        pass


class HTTPBasicAuthClient(IAuthenticatedHTTPClientBase):
    """
    Simple base client type for operations with no auth needed
    """

    client_config = {
        "max_retries": 3,
        "conn_timeout": 3,
        "read_timeout": 60,
        "verify": True,
    }

    def __init__(
        self,
        username,
        password,
        connect_timeout=None,
        read_timeout=None,
        retries=None,
        verify=True,
    ):
        self.auth_config = copy.copy(self.client_config)
        self._user = username
        self.password = password
        self.retries = retries

        if connect_timeout:
            self.auth_config["conn_timeout"] = connect_timeout
        if read_timeout:
            self.auth_config["read_timeout"] = read_timeout
        if retries:
            self.auth_config["max_retries"] = retries

        self.auth_config["verify"] = verify

    @property
    def user(self):
        return self._user

    def _map_error_to_exception(self, exc, username, url=None):
        if exc.response.status_code == 401:
            raise InvalidCredentialsError(username, url)
        elif exc.response.status_code == 403:
            raise InsufficientAccessTierError(
                "Access denied due to insufficient permissions for user: {}".format(
                    username
                )
            )
        else:
            raise Exception(
                "Feed operation failed for user: {}. Msg: {}. Response: {}".format(
                    self.user, exc.response, exc.response.body
                )
            )

    def authenticated_get(
        self, url, connect_timeout=None, read_timeout=None, retries=None
    ):
        return self.execute_request(
            requests.get, url, connect_timeout, read_timeout, retries
        )

    def execute_request(
        self, method, url, connect_timeout=None, read_timeout=None, retries=None
    ):
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
            connect_timeout = int(self.auth_config["conn_timeout"])

        if not read_timeout:
            read_timeout = int(self.auth_config["read_timeout"])

        if not retries:
            retries = int(self.auth_config["max_retries"])
        retries = int(retries)

        verify = self.auth_config["verify"]

        ret = {"status_code": 1, "content": "", "success": False}

        success = False
        count = 0

        conn_timeout = int(connect_timeout)
        read_timeout = int(read_timeout)

        while not success and count < retries:
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                auth = (self.user, self.password)
                logger.debug(
                    "making authenticated request (user={}, conn_timeout={}, read_timeout={}, verify={}) to url {}".format(
                        str(self.user), conn_timeout, read_timeout, verify, str(url)
                    )
                )
                r = method(
                    url, auth=auth, timeout=(conn_timeout, read_timeout), verify=verify
                )
                logger.debug("\tresponse status_code: " + str(r.status_code))
                if r.status_code == 401:
                    logger.debug(
                        "Got HTTP 401 on authenticated {}, response body: {}".format(
                            method.__name__, str(r.text)
                        )
                    )
                    r.raise_for_status()
                elif r.status_code == 200:
                    success = True
                    ret["success"] = True
                elif r.status_code in [403, 404]:
                    r.raise_for_status()

                ret["status_code"] = r.status_code
                ret["content"] = r.content
            except requests.exceptions.ConnectTimeout as err:
                logger.debug("attempt failed: " + str(err))
                ret["content"] = ensure_bytes("server error: timed_out: " + str(err))
                # return(ret)

            except requests.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._map_error_to_exception(e, username=self.user, url=url)
                    # raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    ret["content"] = ensure_bytes("server error: " + str(e))
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                ret["content"] = ensure_bytes("server error: " + str(err))

        return ret


class AnchoreIOClientError(AnchoreException):
    def __init__(
        self,
        cause,
        msg="Error initializing anchore.io client with configured credentials",
    ):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return "{} - exception: {}".format(self.msg, self.cause)

    def __str__(self):
        return "{} - exception: {}".format(self.msg, self.cause)
