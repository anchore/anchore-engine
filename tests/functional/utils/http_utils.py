import json
import requests
import os

CONTENT_TYPE_HEADER = {'Content-Type': 'application/json'}
DEFAULT_API_CONF = {
    'ANCHORE_API_USER': 'admin',
    'ANCHORE_API_PASS': 'foobar',
    'ANCHORE_BASE_URL': 'http://localhost:8228/v1',
    'ANCHORE_API_ACCOUNT': 'admin'
}


def get_api_conf():
    api_conf = DEFAULT_API_CONF
    for key in DEFAULT_API_CONF.keys():
        env_value = os.environ.get(key)
        if env_value:
            api_conf[key] = env_value
    return api_conf


class APIResponse(object):
    def __init__(self, status_code, response=None):
        self.code = status_code
        if response is not None:
            self.url = response.url
            try:
                self.body = response.json()
            except ValueError:
                self.body = response.text or ''

    def __eq__(self, other):
        return isinstance(other, APIResponse) and self.code == other.code

    def __str__(self):
        api_resp_str = 'APIResponse(code={}'.format(self.code)
        if hasattr(self, 'url') and self.url:
            api_resp_str += ', url={}'.format(self.url)
        if hasattr(self, 'body') and self.body:
            api_resp_str += ', body={}'.format(self.body)
        api_resp_str += ')'
        return api_resp_str

    def __repr__(self):
        return str(self)


class RequestFailedError(Exception):
    def __init__(self, url, status_code, body):
        self.url = url
        self.status_code = status_code
        self.body = body

    def __str__(self):
        return 'Request to {} failed with Status Code {} and Body {}'.format(self.url, self.status_code, self.body)


class InsufficientRequestDetailsError(Exception):
    def __init__(self, missing_field_names):
        self.missing_field_names = missing_field_names

    def __str__(self):
        return 'Insufficient Request Details given, cannot make request: {}'.format(', '.join(self.missing_field_names))


def build_url(path_parts, config):
    if path_parts:
        path_parts = os.path.join(*path_parts)
        return os.path.join(config['ANCHORE_BASE_URL'], path_parts)
    return config['ANCHORE_BASE_URL']


def get_headers(config, content_type_override=None):
    headers = content_type_override or CONTENT_TYPE_HEADER
    headers['x-anchore-account'] = config['ANCHORE_API_ACCOUNT']
    return headers


def http_post(path_parts, payload, query=None, config: callable = get_api_conf):

    api_conf = config()

    if path_parts is None:
        raise InsufficientRequestDetailsError(['path_parts'])

    resp = requests.post(build_url(path_parts, api_conf),
                         data=json.dumps(payload),
                         auth=(api_conf['ANCHORE_API_USER'], api_conf['ANCHORE_API_PASS']),
                         headers=get_headers(api_conf),
                         params=query)

    return APIResponse(resp.status_code, response=resp)


def http_get(path_parts, query=None, config: callable = get_api_conf):

    api_conf = config()

    if path_parts is None:
        raise InsufficientRequestDetailsError(['path_parts'])

    resp = requests.get(build_url(path_parts, api_conf),
                        auth=(api_conf['ANCHORE_API_USER'], api_conf['ANCHORE_API_PASS']),
                        headers=get_headers(api_conf),
                        params=query)

    return APIResponse(resp.status_code, response=resp)


def http_del(path_parts, query=None, config: callable = get_api_conf):

    api_conf = config()

    if path_parts is None:
        raise InsufficientRequestDetailsError(['path_parts'])

    resp = requests.delete(build_url(path_parts, api_conf),
                           auth=(api_conf['ANCHORE_API_USER'], api_conf['ANCHORE_API_PASS']),
                           headers=get_headers(api_conf),
                           params=query)

    return APIResponse(resp.status_code, resp)


def http_put(path_parts, payload, query=None, config: callable = get_api_conf):

    api_conf = config()

    if path_parts is None:
        raise InsufficientRequestDetailsError(['path_parts'])

    resp = requests.put(build_url(path_parts, api_conf),
                        data=json.dumps(payload),
                        auth=(api_conf['ANCHORE_API_USER'], api_conf['ANCHORE_API_PASS']),
                        headers=get_headers(api_conf),
                        params=query)

    return APIResponse(resp.status_code, response=resp)


def http_post_url_encoded(path_parts, payload=None, query=None, config: callable = get_api_conf):

    api_conf = config()

    if path_parts is None:
        raise InsufficientRequestDetailsError(['path_parts'])

    resp = requests.post(build_url(path_parts, api_conf),
                         data=payload,
                         auth=(api_conf['ANCHORE_API_USER'], api_conf['ANCHORE_API_PASS']),
                         headers=get_headers(api_conf, {'Content-Type': 'application/x-www-form-urlencoded'}),
                         params=query)

    return APIResponse(resp.status_code, response=resp)
