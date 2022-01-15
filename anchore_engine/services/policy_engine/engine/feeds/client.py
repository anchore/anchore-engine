import abc
import copy
import datetime
import json
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Dict, Optional, Tuple, Union

import ijson
import requests
import requests.exceptions

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.common.models.schemas import (
    FeedAPIGroupRecord,
    FeedAPIRecord,
    GrypeDBListing,
)
from anchore_engine.services.policy_engine.engine.feeds import (
    FeedGroupList,
    FeedList,
    GroupData,
    IFeedSource,
)
from anchore_engine.services.policy_engine.engine.feeds.config import SyncConfig
from anchore_engine.subsys import logger
from anchore_engine.util.time import rfc3339str_to_datetime
from anchore_engine.utils import (
    AnchoreException,
    CommandException,
    ensure_bytes,
    ensure_str,
)

FEED_DATA_ITEMS_PATH = "data.item"
FEED_DATA_NEXT_TOKEN_PATH = "next_token"


@dataclass
class HTTPClientResponse:
    content_type: Optional[str] = None
    status_code: int = 1
    content: bytes = b""
    success: bool = False
    headers: Dict[str, Any] = field(default_factory=dict)


class HTTPClientException(AnchoreException):
    pass


class HTTPStatusException(HTTPClientException):
    def __init__(self, client_response: HTTPClientResponse):
        try:
            body_content = f" {client_response.content.decode('utf-8')}"
        except UnicodeDecodeError:
            body_content = ""
        error_msg = f"Non-200 HTTP Status. The HTTP request generated a status of {client_response.status_code}{body_content}."
        super().__init__(self, error_msg)


class InsufficientAccessTierError(HTTPClientException):
    pass


class InvalidCredentialsError(HTTPClientException):
    def __init__(self, username, target):
        super().__init__(
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
    ) -> HTTPClientResponse:
        return self.execute_request(
            requests.get, url, connect_timeout, read_timeout, retries
        )

    def execute_request(
        self, method, url, connect_timeout=None, read_timeout=None, retries=None
    ) -> HTTPClientResponse:
        """
        Execute an HTTP request with auth params and the specified timeout overrides

        :param method: a callable for the http method to execute (e.g. requests.get, requests.put, ...)
        :param url:
        :param connect_timeout:
        :param read_timeout:
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

        client_response = HTTPClientResponse()

        success = False
        count = 0

        conn_timeout = int(connect_timeout)
        read_timeout = int(read_timeout)

        while not success and count < retries:
            count += 1
            logger.debug("get attempt " + str(count) + " of " + str(retries))
            try:
                logger.debug(
                    "making authenticated request (user={}, conn_timeout={}, read_timeout={}, verify={}) to url {}".format(
                        str(self.user), conn_timeout, read_timeout, verify, str(url)
                    )
                )
                # TODO: move un-authed requests to new class or rename this class
                auth = None
                if self.user or self.password:
                    auth = (self.user, self.password)
                r = method(
                    url, auth=auth, timeout=(conn_timeout, read_timeout), verify=verify
                )
                logger.debug("\tresponse status_code: " + str(r.status_code))
                if r.status_code == 200:
                    success = True
                    client_response.success = True
                elif r.status_code == 401:
                    logger.debug(
                        "Got HTTP 401 on authenticated {}, response body: {}".format(
                            method.__name__, str(r.text)
                        )
                    )
                    r.raise_for_status()
                elif r.status_code in [403, 404]:
                    r.raise_for_status()

                client_response.status_code = r.status_code
                client_response.content_type = r.headers["Content-Type"]
                client_response.content = r.content
                client_response.headers = r.headers
            except requests.exceptions.ConnectTimeout as err:
                logger.debug("attempt failed: " + str(err))
                client_response.content = ensure_bytes(
                    "server error: timed_out: " + str(err)
                )
                # return(ret)

            except requests.HTTPError as e:
                if e.response is not None and 400 <= e.response.status_code < 500:
                    self._map_error_to_exception(e, username=self.user, url=url)
                    # raise e
                else:
                    logger.debug("attempt failed: " + str(e))
                    client_response.content = ensure_bytes("server error: " + str(e))
            except Exception as err:
                logger.debug("attempt failed: " + str(err))
                client_response.content = ensure_bytes("server error: " + str(err))

        return client_response


class FeedClientError(AnchoreException):
    pass


class UnexpectedMIMEType(FeedClientError):
    def __init__(self, mime_type: str):
        super().__init__(
            f"Unexpected MIME type {mime_type} was encountered while downloading feed data."
        )


class FeedServiceClient(IFeedSource):
    """
    Base client class with no auth
    """

    def __init__(
        self,
        feeds_endpoint: str,
        http_client: HTTPBasicAuthClient,
    ):
        if not feeds_endpoint:
            raise ValueError("endpoint cannot be None")

        self.http_client = http_client
        self.feed_url = feeds_endpoint
        self.group_url = self.feed_url + "/{feed}"
        self.group_data_url = self.group_url + "/{group}"
        self.retry_count = 3

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

                if record.success:
                    data = json.loads(ensure_str(record.content))
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
                        "Feed list operation failed. Msg: {}.".format(record.content)
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
                if record.success:
                    data = json.loads(ensure_str(record.content))
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
                        "Feed list operation failed. Msg: {}.".format(record.content)
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
            if record.success:
                if record.content_type != "application/json":
                    raise UnexpectedMIMEType(record.content_type)
                next_token, group_data, count = self._extract_response_data(
                    record.content
                )
                return GroupData(
                    data=group_data,
                    next_token=next_token,
                    since=since,
                    record_count=count,
                    response_metadata={},
                )
            else:
                raise Exception(
                    "Feed list operation failed. Msg: {}.".format(record.content)
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
    ) -> HTTPClientResponse:
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

    @staticmethod
    def _extract_response_data(response_text):
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
        for _ in ijson.items(sio, FEED_DATA_ITEMS_PATH):
            count += 1

        logger.debug("Found {} records in data chunk".format(count))
        sio.close()

        return next_token, response_text, count


class GrypeDBUnavailable(FeedClientError):
    def __init__(self, db_version: str):
        super().__init__(
            f"No valid Grype DBs matching version {db_version} are available on the upstream service."
        )


class GrypeVersionCommandError(FeedClientError):
    pass


class InvalidGrypeVersionResponse(GrypeVersionCommandError):
    def __init__(self, response_string: str):
        super().__init__(
            f"The 'grype version' command did not return the expected response. Response: {response_string}"
        )


class GrypeDBServiceClient(IFeedSource):
    """
    Client for upstream service (toolbox service or feeds service) serving Grype DB.

    :param grype_db_endpoint: base URL of toolbox service
    :type grype_db_endpoint: str
    :param http_client: configured and instantiated http client to use
    :type http_client: HTTPBasicAuthClient
    """

    RETRY_COUNT = 3

    def __init__(
        self,
        grype_db_endpoint: str,
        http_client: HTTPBasicAuthClient,
    ):
        self.feed_url = grype_db_endpoint
        self.http_client = http_client

    def list_feeds(self) -> FeedList:
        """
        Returns metadata to support existing Feeds Service metadata model.
        This is what essentially creates the FeedMetadata object for 'grypedb'.
        Shoehorning the GrypeDB into the Feeds Service metadata model is a hack,
        but is likely necessary evil until legacy feeds are deprecated and the model
        can be redesigned and refactored.

        :return: statically generated FeedList response model
        :rtype: FeedList
        """
        return FeedList(
            feeds=[
                FeedAPIRecord(
                    name="grypedb",
                    description="grypedb feed",
                    access_tier="0",
                )
            ]
        )

    def _list_feed_groups(self) -> Dict[str, Union[int, str]]:
        """
        Sends HTTP request to toolbox service's listing.json endpoint.
        loads and parses the response, returning the first result with the version that applies to the version of Grype
        that is installed in the container.

        :return: Grype DB listing.json
        :rtype: Dict[str, Union[int, str]
        """
        logger.info("Downloading grypedb listing.json from %s", self.feed_url)
        listing_response = self.http_client.execute_request(
            requests.get, self.feed_url, retries=self.RETRY_COUNT
        )
        if not listing_response.success:
            raise HTTPStatusException(listing_response)
        listings_json = json.loads(listing_response.content.decode("utf-8"))
        required_grype_db_version = self._get_supported_grype_db_version()
        available_dbs = listings_json.get("available").get(required_grype_db_version)
        if not available_dbs:
            raise GrypeDBUnavailable(required_grype_db_version)
        raw_db_listing = available_dbs[0]
        logger.info("Found relevant grypedb listing: %s", raw_db_listing)
        return raw_db_listing

    def list_feed_groups(self, feed: str) -> FeedGroupList:
        """
        Retrieves the latest Grype DB listing.json.

        :param feed:
        :type feed: str
        :return: FeedGroupList object, containing one FeedAPIGroupRecord that has the GrypeDBListing information
        :rtype: FeedGroupList
        """
        raw_db_listing = self._list_feed_groups()
        grype_db_listing = dict(raw_db_listing)
        grype_db_listing["built"] = rfc3339str_to_datetime(raw_db_listing["built"])
        return FeedGroupList(
            groups=[
                FeedAPIGroupRecord(
                    name="grypedb:vulnerabilities",
                    description="grypedb:vulnerabilities group",
                    access_tier="0",
                    grype_listing=GrypeDBListing(**grype_db_listing),
                )
            ]
        )

    @staticmethod
    def _get_supported_grype_db_version() -> str:
        """
        Retrieves the supported Grype DB version from the installed copy of Grype using the grype wrapper.

        :return: supported grype DB version
        :rtype: str
        """
        grype_wrapper = GrypeWrapperSingleton.get_instance()
        try:
            version_response = grype_wrapper.get_grype_version()
        except CommandException as exc:
            raise GrypeVersionCommandError() from exc
        try:
            return str(version_response["supportedDbSchema"])
        except KeyError as exc:
            raise InvalidGrypeVersionResponse(json.dumps(version_response)) from exc

    def _get_feed_group_data(self) -> Tuple[Dict, HTTPClientResponse]:
        """
        Sends HTTP request to toolbox service URL in listing.json to retrieve a single grype DB.
        This is painfully written because of legacy compatibility constraints.
        Ideally, listing.json would be passed in by download machinery. We're calling _list_feed_groups()
        here, as changing the signature would break Liskov substitution principle and cluttering a soon-to-be
        obsolete interface with more params is unlikely to be a productive exercise.

        :return: tuple containing the raw listing.json and the HTTPClientResponse for the DB download
        :rtype: Tuple[Dict, HTTPClientResponse]
        """
        grype_db_listing = self._list_feed_groups()
        grype_db_url = grype_db_listing["url"]
        logger.info("Downloading grypedb %s", grype_db_url)
        grype_db_download_response = self.http_client.execute_request(
            requests.get, grype_db_url, retries=self.RETRY_COUNT
        )
        if not grype_db_download_response.success:
            raise HTTPStatusException(grype_db_download_response)
        return grype_db_listing, grype_db_download_response

    def get_feed_group_data(
        self,
        feed: str,
        group: str,
        since: Optional[datetime.datetime] = None,
        next_token: str = None,
    ) -> GroupData:
        """
        Retrieves a single Grype DB, storing the raw bytes in GroupData.data.

        :param feed: feed name (unused)
        :type feed: str
        :param group: group name (unused)
        :type group: str
        :param since: filter for time record was created (unused)
        :type since: Optional[datetime.datetime]
        :param next_token: token for pagination (unused)
        :type next_token: str
        :return: GroupData where GroupData.data contains the raw bytes and GroupData.response_metadata contains the listing information.
        :rtype: GroupData
        """
        try:
            listing_json, record = self._get_feed_group_data()
            if record.content_type != "application/x-tar":
                raise UnexpectedMIMEType(record.content_type)
            return GroupData(
                data=record.content,
                next_token=None,
                since=since,
                record_count=1,
                response_metadata={
                    "checksum": listing_json.get("checksum"),
                    "built": listing_json.get("built"),
                    "version": listing_json.get("version"),
                },
            )
        except (HTTPStatusException, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug("Error executing grype DB data download: %s", e)
            raise e


def get_feeds_client(sync_config: SyncConfig) -> FeedServiceClient:
    """
    Returns a configured client based on the provided config

    :param sync_config: configuration
    :type sync_config: SyncConfig
    :return: initialized FeedServiceClient
    :rtype: FeedServiceClient
    """

    logger.debug(
        "Initializing a feeds client: url=%s, user=%s, conn_timeout=%s, read_timeout=%s",
        sync_config.url,
        sync_config.username,
        sync_config.connection_timeout_seconds,
        sync_config.read_timeout_seconds,
    )

    return FeedServiceClient(
        feeds_endpoint=sync_config.url,
        http_client=HTTPBasicAuthClient(
            username=sync_config.username,
            password=sync_config.password,
            connect_timeout=sync_config.connection_timeout_seconds,
            read_timeout=sync_config.read_timeout_seconds,
            verify=sync_config.ssl_verify,
        ),
    )


def get_grype_db_client(sync_config: SyncConfig) -> GrypeDBServiceClient:
    """
    Returns a configured client based on the local config.

    :param sync_config: configuration
    :type sync_config: SyncConfig
    :return: initialized GrypeDBServiceClient
    :rtype: GrypeDBServiceClient
    """

    logger.debug(
        "Initializing a grype db client: url=%s, conn_timeout=%d, read_timeout=%d",
        sync_config.url,
        sync_config.connection_timeout_seconds,
        sync_config.read_timeout_seconds,
    )

    return GrypeDBServiceClient(
        grype_db_endpoint=sync_config.url,
        http_client=HTTPBasicAuthClient(
            username=None,
            password=None,
            connect_timeout=sync_config.connection_timeout_seconds,
            read_timeout=sync_config.read_timeout_seconds,
            verify=sync_config.ssl_verify,
        ),
    )
