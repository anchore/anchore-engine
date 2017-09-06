import datetime
import json
import logging
import re
import urlparse
# urllib3 throws some ssl warnings with older versions of python
#   they're probably ok for the registry client to ignore
import warnings

from requests import get, put, delete, head
from requests.exceptions import HTTPError

warnings.filterwarnings("ignore")


logger = logging.getLogger(__name__)


class CommonBaseClient(object):
    def __init__(self, host, verify_ssl=None, username=None, password=None):
        self.host = host

        self.method_kwargs = {}
        if verify_ssl is not None:
            self.method_kwargs['verify'] = verify_ssl
        if username is not None and password is not None:
            self.method_kwargs['auth'] = (username, password)
    
    def _http_response(self, url, method, data=None, headers={}, **kwargs):
        """url -> full target url
           method -> method from requests
           data -> request body
           kwargs -> url formatting args
        """
        if data and 'content-type' not in headers and 'Content-Type' not in headers:
            headers['content-type'] = 'application/json'
            data = json.dumps(data)

        path = url.format(**kwargs)
        #path = urllib.quote(path)
        logger.debug("%s %s", method.__name__.upper(), path)
        response = method(self.host + path,
                          data=data, headers=headers, **self.method_kwargs)
        logger.debug("%s %s", response.status_code, response.reason)
        if response.status_code == 307 or response.status_code == 301:
            redirect_url = urlparse.urlparse(response.headers['Location'])
            response = method(redirect_url.geturl(), data=data, headers=headers, **self.method_kwargs)
        if not response.ok:
            logger.debug("Error response: %r", response.text)
            response.raise_for_status()

        return response

    def _http_call(self, url, method, data=None, headers={}, **kwargs):
        """url -> full target url
           method -> method from requests
           data -> request body
           kwargs -> url formatting args
        """
        response = self._http_response(url, method, data=data, headers=headers, **kwargs)
        if method == head and not response.content:
            return response.headers

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError:
            logger.error("Unable to decode json for response %r, url %s",
                         response.text, url.format(**kwargs))
            raise


class OAuth2TokenHandler:
    """
    Handles the token fetch and caching.
    Caches by url and token scope.

    """
    authorization_header_format = 'Bearer {0}'
    _www_authentication_regex = 'Bearer (realm="[^"]+")(,service="[^"]+")?(,scope="[^"]+")?'

    def __init__(self, username=None, passwd=None):
        self._tokens = {}
        self._www_auth_matcher = re.compile(self._www_authentication_regex)
        self.username = username
        self.password = passwd

    def _add_token(self, path, url, params, raw_token):
        now = datetime.datetime.utcnow()
        expiration = now + datetime.timedelta(seconds=int(raw_token.get('expires_in', 300)))
        self._tokens[path] = {'urls': [url], 'params':params, 'raw_token': raw_token, 'timestamp': now, 'expiration': expiration}

    def lookup_by_url(self, url):
        found = self._tokens[url]
        if found:
            if found['expiration'] > datetime.datetime.utcnow():
                return found['raw_token']
            else:
                logger.debug('Found cached token, but it is expired. Flushing and failing cache lookup')
                self.invalidate_token(found['raw_token']['token'])
        raise KeyError(url)

    def lookup_by_params(self, params):
        """
        Lookup by the service and scope. If multiple results found, return the first

        :param params:
        :return: token associated with params values (e.g. scope, service)
        """
        matches = filter(lambda x: x['params'] == params, self._tokens.values())
        if len(matches) > 0:
            for m in matches:
                if m['expiration'] > datetime.datetime.utcnow():
                    return m['raw_token']
                else:
                    logger.debug('Found cached token, but it is expired. Flushing and failing cache lookup')
                    self.invalidate_token(m['raw_token']['token'])
        raise KeyError(params)

    def _parse_wwwauthenticate(self, header):
        header = header.strip()
        header_match = self._www_auth_matcher.search(header)
        if len(header_match.groups()) <= 0:
            raise ValueError('Unexpected header value. Should start with Bearer token')

        params = {}
        for chunk in header_match.groups():
            if chunk is not None:
                c = chunk.split('=')
                params[c[0].lstrip(',')] = c[1].strip('"')

        try:
            return params.pop('realm'), params
        except KeyError:
            raise ValueError('Error header should include a realm key')

    def invalidate_token(self, token):
        """
        Invalidate the cache entry for the token value
        :param token:
        :return:
        """
        self._flush_token(token)

    def _flush_token(self, token):
        """
        Flush a cache entry by the actual token value
        :param token:
        :return:
        """
        logger.debug('Flushing token: {}'.format(token))
        for url, cached_token in self._tokens.items():
            if cached_token['raw_token']['token'] == token:
                self._tokens.pop(url)

    @staticmethod
    def needs_token(err_response):
        return 400 <= err_response.status_code < 500 and err_response.reason == 'Unauthorized'

    @staticmethod
    def token_is_invalid(err_response):
        """
        Determine if the response is due to invalid token.
        :param err_response: the _http_response() output of the request to check. Should include the original request
        :return: token value from request if invalid, else False
        """
        if OAuth2TokenHandler.needs_token(err_response) \
            and 'Authorization' in err_response.request.headers \
            and 'www-authenticate' in err_response.headers \
            and err_response.headers['www-authenticate'].find('error="invalid_token"') > 0:
            logger.debug('Received response from server indicating expired/invalid token: {}'.format(err_response.headers))
            return err_response.request.headers['Authorization'].split(' ')[1]
        else:
            return False

    def request_auth_token(self, err_response, path, use_cache=True):
        """
        Get a token from the passed error response that indicates a required token. Uses cache
        :param err_response: the error response indicating a token needed
        :param use_cache: use a token cache to avoid repeat requests. Default=True
        :return:
        """

        # Was the token in the original request invalid?
        invalid_token = OAuth2TokenHandler.token_is_invalid(err_response)
        # Flush the old token and get a new one. Tokens timeout
        if invalid_token:
            self._flush_token(invalid_token)

        # Parse the error response to get auth info
        try:
            req_url = err_response.request.url
            auth_url, req_params = self._parse_wwwauthenticate(err_response.headers['www-authenticate'])
            logger.debug('Getting auth token from auth url: {0} and params {1}'.format(auth_url, req_params))
        except KeyError:
            # No header for auth means no token needed
            return None

        # Do we already have the proper scoped token in the cache?
        if use_cache:
            try:
                cached_token = self.lookup_by_params(req_params)
                logger.debug('Found valid cached token: {}'.format(cached_token))
                return cached_token
            except KeyError:
                pass

        try:
            logger.debug('No valid cache entry found. Requesting a new token from {0} with params {1}'.format(auth_url, req_params))
            if self.username and self.password:
                response = get(auth_url, params=req_params, auth=(self.username, self.password))
            else:
                response = get(auth_url, params=req_params)
            self._add_token(path=path, url=req_url, params=req_params, raw_token=response.json())
            logger.debug('Added new token to cache and returning to caller')
            return self._tokens[path]['raw_token']
        except HTTPError, e:
            raise e


class AuthCommonBaseClient(CommonBaseClient):

    def __init__(self, host, verify_ssl=None, username=None, password=None):
        super(AuthCommonBaseClient, self).__init__(host, verify_ssl, username=None, password=None)
        self.token_handler = OAuth2TokenHandler(username, password)

    @staticmethod
    def _add_auth(token, headers=None):
        if headers is None:
            headers = {}

        headers['Authorization'] = OAuth2TokenHandler.authorization_header_format.format(token)
        return headers

    def _http_response(self, url, method, data=None, headers=None, **kwargs):
        path = url.format(**kwargs)
        if not headers:
            headers = {}

        try:
            # If there is a token for this url, use it
            try:
                token = self.token_handler.lookup_by_url(path)
                headers = AuthCommonBaseClient._add_auth(token['token'], headers)
            except KeyError:
                pass

            response = super(AuthCommonBaseClient, self)._http_response(url, method, data=data, headers=headers, **kwargs)
            return response
        except HTTPError, e:

            if OAuth2TokenHandler.needs_token(e.response):
                token = self.token_handler.request_auth_token(e.response, path)
                if token:
                    headers = AuthCommonBaseClient._add_auth(token['token'], headers=headers)
                    try:
                        response = super(AuthCommonBaseClient, self)._http_response(url, method, data=data,
                                                                                headers=headers,
                                                                                **kwargs)
                        return response
                    except HTTPError, e:
                        raise e

                else:
                    raise Exception('No token found or fetched. Cannot proceed.')
            else:
                # Not a token problem. Just raise error
                raise e

    def _http_call(self, url, method, data=None, **kwargs):
        path = url.format(**kwargs)
        header = {}
        try:
            # If there is a token for this url, use it
            try:
                token = self.token_handler.lookup_by_url(path)
                header['Authorization'] = OAuth2TokenHandler.authorization_header_format.format(token['token'])
            except KeyError:
                pass

            response = super(AuthCommonBaseClient, self)._http_call(url, method, data=data, headers=header, **kwargs)
            return response
        except HTTPError, e:
            if OAuth2TokenHandler.needs_token(e.response):
                invalid_token = OAuth2TokenHandler.token_is_invalid(e.response)
                if invalid_token:
                    self.token_handler.invalidate_token(invalid_token)
                #else:
                try:
                    cached_token = self.token_handler.lookup_by_url(path)
                    token = cached_token
                except KeyError:
                    token = self.token_handler.request_auth_token(e.response, path)

                if token:
                    header['Authorization'] = 'Bearer ' + self.token_handler.request_auth_token(e.response, path)['token']
                    try:
                        response = super(AuthCommonBaseClient, self)._http_call(url, method, data=data, headers=header,
                                                                                **kwargs)
                        return response
                    except HTTPError, e:
                        raise e

                else:
                    raise Exception('No token found or fetched. Cannot proceed.')
            else:
                # Not a token problem. Just raise error
                raise e


class BaseClientV1(CommonBaseClient):
    IMAGE_LAYER = '/v1/images/{image_id}/layer'
    IMAGE_JSON = '/v1/images/{image_id}/json'
    IMAGE_ANCESTRY = '/v1/images/{image_id}/ancestry'
    REPO = '/v1/repositories/{namespace}/{repository}'
    TAGS = REPO + '/tags'

    @property
    def version(self):
        return 1

    def search(self, q=''):
        """GET /v1/search"""
        if q:
            q = '?q=' + q
        return self._http_call('/v1/search' + q, get)

    def check_status(self):
        """GET /v1/_ping"""
        return self._http_call('/v1/_ping', get)

    def get_images_layer(self, image_id):
        """GET /v1/images/{image_id}/layer"""
        return self._http_call(self.IMAGE_LAYER, get, image_id=image_id)

    def put_images_layer(self, image_id, data):
        """PUT /v1/images/(image_id)/layer"""
        return self._http_call(self.IMAGE_LAYER, put,
                               image_id=image_id, data=data)

    def put_image_layer(self, image_id, data):
        """PUT /v1/images/(image_id)/json"""
        return self._http_call(self.IMAGE_JSON, put,
                               data=data, image_id=image_id)

    def get_image_layer(self, image_id):
        """GET /v1/images/(image_id)/json"""
        return self._http_call(self.IMAGE_JSON, get, image_id=image_id)

    def get_image_ancestry(self, image_id):
        """GET /v1/images/(image_id)/ancestry"""
        return self._http_call(self.IMAGE_ANCESTRY, get, image_id=image_id)

    def get_repository_tags(self, namespace, repository):
        """GET /v1/repositories/(namespace)/(repository)/tags"""
        return self._http_call(self.TAGS, get,
                               namespace=namespace, repository=repository)

    def get_image_id(self, namespace, respository, tag):
        """GET /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, get,
                               namespace=namespace, repository=respository)

    def get_tag_json(self, namespace, repository, tag):
        """GET /v1/repositories(namespace)/(repository)tags(tag*)/json"""
        return self._http_call(self.TAGS + '/' + tag + '/json', get,
                               namespace=namespace, repository=repository)

    def delete_repository_tag(self, namespace, repository, tag):
        """DELETE /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, delete,
                               namespace=namespace, repository=repository)

    def set_tag(self, namespace, repository, tag, image_id):
        """PUT /v1/repositories/(namespace)/(repository)/tags/(tag*)"""
        return self._http_call(self.TAGS + '/' + tag, put, data=image_id,
                               namespace=namespace, repository=repository)

    def delete_repository(self, namespace, repository):
        """DELETE /v1/repositories/(namespace)/(repository)/"""
        return self._http_call(self.REPO, delete,
                               namespace=namespace, repository=repository)


class BaseClientV2(AuthCommonBaseClient):
    LIST_TAGS = '/v2/{name}/tags/list'
    MANIFEST = '/v2/{name}/manifests/{reference}'
    BLOB = '/v2/{name}/blobs/{digest}'
    _v1_media_types = ','.join(['application/vnd.docker.distribution.manifest.v1+json','application/vnd.docker.distribution.manifest.v1+prettyjws'])
    _v2_media_types = ','.join(['application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.docker.distribution.manifest.v2+json'])
    _all_accept_media_types = ','.join([_v2_media_types, _v1_media_types])

    def __init__(self, *args, **kwargs):
        super(BaseClientV2, self).__init__(*args, **kwargs)
        self._manifest_digests = {}

    @property
    def version(self):
        return 2

    def check_status(self):
        return self._http_call('/v2/', get)

    def catalog(self):
        return self._http_call('/v2/_catalog', get)

    def get_repository_tags(self, name):
        return self._http_call(self.LIST_TAGS, get, name=name)

    def get_blob(self, name, digest):
        return self._http_response(self.BLOB, get, name=name, digest=digest)

    def get_manifest_digest(self, name, reference):
        custom_headers = {
            'Accept': self._all_accept_media_types
        }
        response = self._http_response(self.MANIFEST, head, name=name, reference=reference, headers=custom_headers)
        return response.headers['Docker-Content-Digest']

    def get_manifest_and_digest(self, name, reference, accept_version=None):
        custom_headers = {
            'Accept': self._all_accept_media_types
        }

        if accept_version:
            if accept_version == 1:
                custom_headers['Accept'] = self._v1_media_types
            elif accept_version == 2:
                custom_headers['Accept'] = self._v2_media_types
            else:
                raise ValueError(accept_version)

        response = self._http_response(self.MANIFEST, get, name=name, reference=reference, headers=custom_headers)
        self._cache_manifest_digest(name, reference, response=response)
        return (response.json(), self._manifest_digests[name, reference])

    def delete_manifest(self, name, digest):
        return self._http_call(self.MANIFEST, delete,
                               name=name, reference=digest)

    def delete_blob(self, name, digest):
        return self._http_call(self.BLOB, delete,
                               name=name, digest=digest)

    def get_blob_meta(self, name, digest, url=None):
        if not url:
            resp = self._http_response(self.BLOB, head, name=name, digest=digest)
        else:
            resp = self._http_response(url, head)
        return resp

    def _cache_manifest_digest(self, name, reference, response=None):
        if not response:
            # TODO: create our own digest
            raise NotImplementedError()

        untrusted_digest = response.headers.get('Docker-Content-Digest')
        self._manifest_digests[(name, reference)] = untrusted_digest


def BaseClient(host, verify_ssl=None, api_version=None, username=None, password=None):
    if api_version == 1:
        return BaseClientV1(host, verify_ssl=verify_ssl, username=username, password=password)
    elif api_version == 2:
        return BaseClientV2(host, verify_ssl=verify_ssl, username=username, password=password)
    elif api_version is None:
        # Try V2 first
        logger.debug("checking for v2 API")
        v2_client = BaseClientV2(host, verify_ssl=verify_ssl, username=username, password=password)
        try:
            v2_client.check_status()
        except HTTPError as e:
            if e.response.status_code == 404:
                logger.debug("falling back to v1 API")
                return BaseClientV1(host, verify_ssl=verify_ssl, username=username, password=password)

            raise
        else:
            logger.debug("using v2 API")
            return v2_client
    else:
        raise RuntimeError('invalid api_version')
