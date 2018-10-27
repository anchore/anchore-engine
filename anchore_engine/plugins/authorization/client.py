import requests
import copy
import json
import datetime
from anchore_engine.subsys import logger
from urllib import parse as urlparse
from anchore_engine.utils import datetime_to_rfc2339


class BasicApiClient(object):
    __headers__ = {
        'Content-Type': 'application/json'
    }

    def __init__(self, url, verify_ssl=False, username=None, password=None):
        """
        :param url: str url (including scheme) for the endpoint
        """
        self.url = url + '/' if url[:-1] != '/' else url # Ensure trailing slash
        self.verify_ssl = verify_ssl
        self.username = username
        self.password = password

    def call_api(self, method: callable, path: str, path_params=None, query_params=None, extra_headers=None, body=None):
        """
        Invoke the api

        :param method: requests function to invoke (eg. requests.get)
        :param path: url path
        :param path_params: path params as dict
        :param query_params: query param dict
        :param extra_headers: header map to merge with default headers for this client
        :param body: string body to send
        :return:
        """
        if path_params:
            path_params = {name: urlparse.quote(value) for name, value in path_params.items()}
            final_url = urlparse.urljoin(self.url, path.format(**path_params))
        else:
            final_url = urlparse.urljoin(self.url, path)

        request_headers = copy.copy(self.__headers__)

        if extra_headers:
            request_headers.update(extra_headers)

        # Remove any None valued query params
        if query_params:
            filtered_qry_params = {k: v for k, v in filter(lambda x: x[1] is not None, query_params.items())}
        else:
            filtered_qry_params = None

        logger.debug(
            'Dispatching: url={url}, headers={headers}, body={body}, params={params}'.format(url=final_url,
                                                                                             headers=request_headers,
                                                                                             body=body[:512] + ('...' if len(body) > 512 else '') if body else body,
                                                                                             params=filtered_qry_params))
        try:
            if self.username and self.password:
                return method(url=final_url, headers=request_headers, data=body, params=filtered_qry_params, auth=(self.username, self.password))
            else:
                return method(url=final_url, headers=request_headers, data=body, params=filtered_qry_params)
        except Exception as e:
            logger.error('Failed client call to url: {}. Response: {}'.format(final_url, e.__dict__))
            raise e


class SimpleJsonModel(object):
    """
    Base type for marshalling to/from json
    """

    @staticmethod
    def _map_type(obj):
        if type(obj) == datetime.datetime:
            return datetime_to_rfc2339(obj)
        elif type(obj) in [list, set]:
            return [SimpleJsonModel._map_type(i) for i in obj]
        elif type(obj) == dict:
            return {k: SimpleJsonModel._map_type(v) for k, v in obj.items()}
        elif isinstance(obj, SimpleJsonModel):
            return obj.to_json()
        else:
            return obj

    def to_json(self):
        return {k : SimpleJsonModel._map_type(v) for k, v in vars(self).items() if not k.startswith('_')}

    @classmethod
    def from_json(cls, json_dict):
        return None


class AuthorizationRequest(SimpleJsonModel):
    def __init__(self, principal=None, actions=None):
        self.principal = principal
        self.actions = actions

    @classmethod
    def from_json(cls, json_dict):
        if set(json_dict.keys()) != {'principal', 'actions'}:
            raise ValueError('Incorrect key set in json obj')

        if type(json_dict.get('actions')) != list:
            raise ValueError('Incorrect actions type, must be a list, found: {}'.format(type(json_dict.get('actions'))))

        ar = AuthorizationRequest(Principal.from_json(json_dict.get('principal')), [Action.from_json(act_obj) for act_obj in json_dict.get('actions')])
        return ar


class AuthorizationDecision(SimpleJsonModel):

    def __init__(self, principal=None, allowed_actions=None, denied_actions=None, is_authorized=False, ttl=-1):
        self.principal = principal
        self.allowed = allowed_actions
        self.denied = denied_actions
        self.ttl = ttl # If < 0, effectively unset, but try to avoid None as a value for an int

    @classmethod
    def from_json(cls, json_dict):
        if set(json_dict.keys()) != {'principal', 'allowed', 'denied', 'ttl'}:
            raise ValueError('Incorrect key set in json obj')

        if type(json_dict.get('allowed')) != list:
            raise ValueError('Incorrect allowed type, must be a list, found: {}'.format(type(json_dict.get('actions'))))

        if type(json_dict.get('denied')) != list:
            raise ValueError('Incorrect denied type, must be a list, found: {}'.format(type(json_dict.get('actions'))))

        ad = AuthorizationDecision(Principal.from_json(json_dict.get('principal')),
                                   [Action.from_json(act) for act in json_dict.get('allowed', [])],
                                   [Action.from_json(act) for act in json_dict.get('denied', [])],
                                   int(json_dict.get('ttl', "-1")))
        return ad


class Action(SimpleJsonModel):
    def __init__(self, domain='*', action='*', target='*'):
        self.domain = domain
        self.action = action
        self.target = target

    @classmethod
    def from_json(cls, json_dict):
        if set(json_dict.keys()) != {'domain', 'action', 'target'}:
            raise ValueError('Incorrect key set in json obj')

        act = Action(json_dict.get('domain'), json_dict.get('action'), json_dict.get('target'))
        return act

    def __eq__(self, other):
        return isinstance(other, Action) and self.domain == other.domain and self.action == other.action and self.target == other.target

    def __hash__(self):
        return (self.domain.__hash__(), self.action.__hash__(), self.target.__hash__()).__hash__()


class Domain(SimpleJsonModel):
    def __init__(self, name):
        self.name = name

    @classmethod
    def from_json(cls, json_dict):
        if list(json_dict.keys()) != ['name']:
            raise ValueError('Incorrect key set in json obj')

        return Domain(json_dict.get('name'))

    def __eq__(self, other):
        return isinstance(other, Domain) and self.name == other.name


class Principal(SimpleJsonModel):
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return isinstance(other, Domain) and self.name == other.name

    @classmethod
    def from_json(cls, json_dict):
        if list(json_dict.keys()) != ['name']:
            raise ValueError('Incorrect key set in json obj')

        return Principal(json_dict.get('name'))


class AuthzPluginHttpClient(BasicApiClient):
    """
    Client for interacting with Authz Plugins
    """

    def healthcheck(self):
        resp = self.call_api(requests.get, 'health')
        if resp.status_code != 200:
            resp.raise_for_status()
        else:
            return True

    def authorize(self, principal: str, action_s: list):
        """
        Authorize the named principal against the set of actions
        :param principal: string name of identity to request authz for
        :param action_s: list of action tuples
        :return:
        """
        if not all(map(lambda x: isinstance(x, Action), action_s)):
            raise ValueError('action_s must be a list of Action objects')

        req = AuthorizationRequest(principal=Principal(principal), actions=action_s)
        payload = json.dumps(req.to_json())
        logger.debug('Invoking authorize with payload: {}'.format(payload))
        resp = self.call_api(requests.post, 'authorize', body=payload)

        if resp.status_code == 200:
            resp_j = resp.json()
            return AuthorizationDecision.from_json(resp_j)
        else:
            resp.raise_for_status()

    def initialize_domain(self, domain: str):
        req = Domain(domain)
        resp = self.call_api(requests.post, 'domains', body=json.dumps(req.to_json()))
        if resp.status_code in [200, 204]:
            return True
        else:
            resp.raise_for_status()

    def delete_domain(self, domain: str):
        req = Domain(domain)
        resp = self.call_api(requests.delete, 'domains', body=json.dumps(req.to_json()))

        if resp.status_code in [200, 204]:
            return True
        else:
            resp.raise_for_status()

    def list_domains(self):
        resp = self.call_api(requests.get, 'domains')        
        if resp.status_code == 200:
            return [Domain(x) for x in resp.json()]
        else:
            resp.raise_for_status()

    def initialize_principal(self, principal: str):
        req = Principal(principal)
        resp = self.call_api(requests.post, 'principals', body=json.dumps(req.to_json()))
        if resp.status_code in [200, 204]:
            return True
        else:
            resp.raise_for_status()

    def delete_principal(self, principal: str):
        req = Principal(principal)
        resp = self.call_api(requests.delete, 'principals', body=json.dumps(req.to_json()))

        if resp.status_code in [200, 204]:
            return True
        else:
            resp.raise_for_status()

    def list_principals(self):
        resp = self.call_api(requests.get, 'principals')        
        if resp.status_code == 200:
            return [Principal(x) for x in resp.json()]
        else:
            resp.raise_for_status()
