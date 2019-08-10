"""
Module for generating and validing oauth tokens for use in the API layer
"""

import copy
import datetime
import uuid
from authlib.jose import jwt
from authlib.jose import JWTClaims

from anchore_engine.configuration import localconfig
from anchore_engine.utils import ensure_bytes
from anchore_engine.subsys import logger

ANCHORE_ISSUER = 'anchore-engine'
ANCHORE_AUDIENCE = 'anchore-engine'
EXPIRATION_LEEWAY_SECONDS = 10
SUPPORTED_ALGORITHMS = ['HS256', 'HS512', 'RS256', 'RS512']

_token_manager = None

class NotConfigured(Exception):
    pass


def load_keys(config: dict):
    """
    Based on the passed configuration, load a dict mapping the key name to bytes of the key

    :param config: dict with specific keys to find keys, paths
    :return:
    """

    keys = {}

    if config:
        if config.get('private_key_path'):
            priv_keypath = config.get('private_key_path')

            with open(priv_keypath, 'rb') as pem_fp:
                keys['private'] = pem_fp.read()

        # TODO add public x509 cert support to get the key from (DER, PEM formats)
        if config.get('public_key_path'):
            pub_keypath = config.get('public_key_path')
            with open(pub_keypath, 'rb') as crt_fp:
                keys['public'] = crt_fp.read()

        elif config.get('secret'):
            keys['secret'] = ensure_bytes(config.get('secret'))

    return keys


class TokenIssuer(object):
    """
    Creates oauth tokens signed by a specific private key
    """

    def __init__(self, key: bytes, alg: str, issuer=ANCHORE_ISSUER):
        assert alg in SUPPORTED_ALGORITHMS

        self.signing_key = key
        self.signing_alg = alg
        self.issuer = issuer

    def generate_token(self, subject):
        """
        Return a tuple of the generated token and its expiration

        :param subject:
        :return:
        """

        if not self.signing_key:
            raise NotConfigured('SP not configured')
        else:
            header = {'alg': self.signing_alg}
            ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

            expiration = ts + datetime.timedelta(seconds=86400)

            payload = {
                'iss': self.issuer,
                'sub': subject,
                'exp': expiration,
                'iat': ts,
                'jti': uuid.uuid4().hex
            }

            return jwt.encode(header=header, payload=payload, key=self.signing_key), expiration


class TokenVerifier(object):
    """
    Verify tokens with a given key
    """

    __claim_options__ = {
        'iss': {
            'essential': True
        },
        'sub': {
            'essential': True
        }
    }

    __claim_params__ = {}

    def __init__(self, key: bytes, alg: str, issuers=[ANCHORE_ISSUER]):
        assert alg in SUPPORTED_ALGORITHMS
        self.claim_options = copy.deepcopy(TokenVerifier.__claim_options__)
        self.claim_params = copy.deepcopy(TokenVerifier.__claim_params__)

        self.key = key
        self.alg = alg
        self.valid_issuers = issuers
        if self.valid_issuers:
            self.claim_options['iss']['values'] = self.valid_issuers

    def verify_token(self, token: bytes) -> JWTClaims:
        claims = jwt.decode(s=token, key=self.key, claims_params=self.claim_params, claims_options=self.claim_options)
        claims.validate()
        return claims


class JwtTokenManager(object):
    def __init__(self, config=None):
        self.config = config
        self.keys = load_keys(config)

        self.issuers = {name: TokenIssuer(key, 'RS256') if name != 'secret' else TokenIssuer(key, 'HS256', issuer=ANCHORE_ISSUER) for name, key in self.keys.items() if name in ['private', 'secret']}
        self.verifiers = {name: TokenVerifier(key, 'RS256', issuers=[ANCHORE_ISSUER]) if name != 'secret' else TokenVerifier(key, 'HS256') for name, key in self.keys.items() if name in ['public', 'secret']}

        if 'public' in self.verifiers.keys():
            self._default_public = 'public'
        else:
            self._default_public = 'secret'

        if 'private' in self.issuers.keys():
            self._default_private = 'private'
        else:
            self._default_private = 'secret'

    def generate_token(self, username, with_key_name=None, return_expiration=False):
        if not with_key_name:
            # If have priv key then use it, else use secret if available
            tok, exp = self.issuers[self._default_private].generate_token(username)
        else:
            tok, exp = self.issuers[with_key_name].generate_token(username)

        if return_expiration:
            return tok, exp
        else:
            return tok

    def verify_token(self, payload: bytes, with_key=None):
        if not with_key:
            return self.verifiers[self._default_public].verify_token(payload)
        else:
            return self.verifiers[with_key].verify_token(payload)

    def default_issuer(self):
        return self.issuers[self._default_private]

    @classmethod
    def load(cls, config: dict):
        return JwtTokenManager(config)


def keys_config_loader():
    """
    Loads the key configuration from the default location

    :return:
    """

    return localconfig.get_config().get('keys')


def token_manager(config=None):
    global _token_manager
    if _token_manager is None:
        if config is None:
            config = keys_config_loader()

        _token_manager = JwtTokenManager.load(config)

    return _token_manager
