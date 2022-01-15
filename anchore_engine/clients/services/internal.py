"""
Internal service client base and common functions

"""

import copy
import urllib
import urllib.parse
from contextlib import contextmanager

from requests.auth import AuthBase, HTTPBasicAuth

from anchore_engine.clients.services.common import (
    get_service_endpoint,
    get_service_endpoints,
)
from anchore_engine.clients.services.http import anchy_get
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import HttpBasicCredential, HttpBearerCredential
from anchore_engine.utils import ensure_str


class BearerTokenAuth(AuthBase):
    def __init__(self, token):
        self.tok = token

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer {}".format(ensure_str(self.tok).strip())
        return r


class InternalServiceUrlProvider(object):
    """
    Lookup handler for IoC pattern with the client

    """

    def get_url(self, servicename, base_route=None):
        endpt = get_service_endpoint(servicename)
        if base_route:
            return "/".join([endpt, base_route])
        else:
            return endpt

    def get_all_urls(self, servicename, base_route=None):
        endpts = get_service_endpoints(servicename)

        if base_route:
            return ["/".join([url, base_route]) for url in endpts]
        else:
            return endpts


default_provider = InternalServiceUrlProvider()


class InternalServiceClient(object):
    __service__ = None
    __api_base__ = None
    __headers__ = {"Content-Type": "application/json"}

    def __init__(
        self,
        credential_fn,
        as_account=None,
        url_provider=default_provider,
        config_provider_fn=localconfig.get_config,
    ):
        """
        Initializes a client for a specific account using the specified credentials (typically the system user credentials)

        :param as_account: The account for which to execute the call as
        """

        # Assert the base type
        self.request_namespace = as_account
        self.auth = None

        self.credential_provider_fn = credential_fn

        self.verify_ssl = True
        self._read_timeout = 0.0
        self._connect_timeout = 0.0

        if config_provider_fn:
            try:
                cfg = config_provider_fn()
            except:
                logger.debug_exception(
                    "Unexpected exception loading configuration from the config provider function"
                )
                raise

            if cfg:
                try:
                    self.verify_ssl = cfg.get("internal_ssl_verify", True)

                    try:
                        self._read_timeout = float(
                            cfg.get("global_client_read_timeout", 0.0)
                        )
                    except ValueError:
                        logger.error(
                            'Invalid value type found in config for "global_client_read_timeout", expected int or float, found {}'.format(
                                type(cfg.get("global_client_read_timeout"))
                            )
                        )
                        pass

                    try:
                        self._connect_timeout = float(
                            cfg.get("global_client_connect_timeout", 0.0)
                        )
                    except ValueError:
                        logger.error(
                            'Invalid value type found in config for "global_client_connect_timeout", expected int or float, found {}'.format(
                                type(cfg.get("global_client_connect_timeout"))
                            )
                        )
                        pass

                    if self._read_timeout < 0:
                        self._read_timeout = 0.0

                    if self._connect_timeout < 0:
                        self._connect_timeout = 0.0
                except:
                    # Default to verify ssl if not set
                    logger.debug_exception(
                        "Could not initialize ssl verification and client timeouts from config due to error"
                    )
                    raise

        self.service_url_provider = url_provider

    def _build_creds(self):
        credential = self.credential_provider_fn()
        if isinstance(credential, HttpBearerCredential):
            token = credential.get_creds()
            auth = BearerTokenAuth(token)

        elif isinstance(credential, HttpBasicCredential):
            auth = HTTPBasicAuth(credential.get_creds()[0], credential.get_creds()[1])
        else:
            raise TypeError("credential not of expected type")
        return auth

    @contextmanager
    def timeout_context(self, connect_timeout=None, read_timeout=None):
        """
        A context manager for using timeout values on a client object within a bound scope.

        Usage example:

        client = InternalServiceClient(...)
        with client.timeout_context(10, 10) as timeout_client:
          response = timeout_client.make_my_call()

        :param connect_timeout:
        :param read_timeout:
        :return:
        """
        original_conn_timeout = self._connect_timeout
        original_read_timeout = self._read_timeout

        try:
            if connect_timeout is not None and connect_timeout > 0:
                self._connect_timeout = connect_timeout
            else:
                self._connect_timeout = 0

            if read_timeout is not None and read_timeout > 0:
                self._read_timeout = read_timeout
            else:
                self._read_timeout = 0

            yield self
        finally:
            self._connect_timeout = original_conn_timeout
            self._read_timeout = original_read_timeout

    def call_api(
        self,
        method: callable,
        path: str,
        path_params=None,
        query_params=None,
        extra_headers=None,
        body=None,
        connect_timeout=None,
        read_timeout=None,
        files=None,
    ):
        """
        Invoke the api against a single service instance

        :param method: requests method function to invoke
        :param path: path str with optional format replacement via str.format(...)
        :param path_params: dict of k/v path params to substitute
        :param query_params: dict of k/v query params
        :param extra_headers: headers to set in request
        :param body: body of request
        :param connect_timeout: Time in seconds to connection established
        :param read_timeout: Time in seconds to first byte of response
        :return:
        """
        # Replace url terms
        base_url = self.service_url_provider.get_url(
            self.__service__, self.__api_base__
        )

        if not connect_timeout and self._connect_timeout:
            connect_timeout = self._connect_timeout
        if not read_timeout and self._read_timeout:
            read_timeout = self._read_timeout

        return self.dispatch(
            base_url,
            method,
            path,
            path_params,
            query_params,
            extra_headers,
            body,
            connect_timeout,
            read_timeout,
            files,
        )

    def dispatch(
        self,
        base_url: str,
        method: callable,
        path: str,
        path_params=None,
        query_params=None,
        extra_headers=None,
        body=None,
        connect_timeout=None,
        read_timeout=None,
        files=None,
    ):
        """
        Execute the request and return the response

        :param base_url:
        :param method:
        :param path:
        :param body:
        :param path_params:
        :param query_params:
        :param extra_headers:
        :return:
        """

        if path_params:
            path_params = {
                name: urllib.parse.quote(value) for name, value in path_params.items()
            }
            final_url = "/".join([base_url, path.format(**path_params)])
        else:
            final_url = "/".join([base_url, path])

        # default is to use the application/json content type, but if 'files' is specified, let requests handle headers for multipart/formdata
        request_headers = copy.copy(self.__headers__)
        if files:
            request_headers = {}

        if self.request_namespace:
            request_headers["x-anchore-account"] = self.request_namespace

        if extra_headers:
            request_headers.update(extra_headers)

        # Remove any None valued query params
        if query_params:
            filtered_qry_params = {
                k: v
                for k, v in filter(lambda x: x[1] is not None, query_params.items())
            }
        else:
            filtered_qry_params = None

        try:
            log_body = (
                ensure_str(body[:512]) + "..." if body and len(body) > 512 else body
            )
        except UnicodeError:
            log_body = f"Unable to decode body for logging (binary string of length {len(body)})."

        logger.debug(
            "Dispatching: url={url}, headers={headers}, body={body}, params={params}, timeout=({conn_timeout}, {read_timeout}), files={files}".format(
                url=final_url,
                headers=request_headers,
                body=log_body,
                params=filtered_qry_params,
                conn_timeout=connect_timeout,
                read_timeout=read_timeout,
                files=files.keys() if files else files,
            )
        )

        auth = self._build_creds()
        try:
            if connect_timeout and connect_timeout <= 0:
                connect_timeout = None
            if read_timeout and read_timeout <= 0:
                read_timeout = None

            if connect_timeout or read_timeout:
                return method(
                    url=final_url,
                    headers=request_headers,
                    data=body,
                    auth=auth,
                    params=filtered_qry_params,
                    verify=self.verify_ssl,
                    timeout=(connect_timeout, read_timeout),
                    files=files,
                )
            else:
                return method(
                    url=final_url,
                    headers=request_headers,
                    data=body,
                    auth=auth,
                    params=filtered_qry_params,
                    verify=self.verify_ssl,
                    files=files,
                )
        except Exception as e:
            logger.debug_exception(
                "Failed client call to service {} for url: {}. Response: {}".format(
                    self.__service__, final_url, e.__dict__
                )
            )
            raise e

    def round_robin_call_api(
        self,
        method: callable,
        path: str,
        path_params=None,
        query_params=None,
        extra_headers=None,
        body=None,
    ):
        """
        Invoke the api against service endpoints until the first non-exception response is received. Will only try another instnace
        if the first is unsuccessfully delivered, e.g. cannot connect. Any valid HTTP response is considered a successful dispatch.

        :param method:
        :param path:
        :param body:
        :param path_params:
        :param query_params:
        :param extra_headers:
        :return:
        """

        urls = self.service_url_provider.get_all_urls(
            self.__service__, self.__api_base__
        )
        last_ex = None
        for base_url in urls:
            try:
                resp = self.dispatch(
                    base_url,
                    method,
                    path,
                    path_params,
                    query_params,
                    extra_headers,
                    body,
                )
                return resp
            except Exception as ex:
                last_ex = ex
        else:
            if last_ex:
                raise last_ex
            else:
                raise Exception(
                    "Client invocation error: unsuccessful response but no exception"
                )

    def status(self):
        return self.call_api(anchy_get, "status")
