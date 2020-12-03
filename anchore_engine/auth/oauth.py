"""
Module for generating and validing oauth tokens for use in the API layer
"""

import copy
import datetime
import uuid
from authlib.jose import jwt
from authlib.jose import JWTClaims
from anchore_engine.configuration import localconfig
from anchore_engine.configuration.localconfig import (
    OauthNotConfiguredError,
    InvalidOauthConfigurationError,
)
from anchore_engine.utils import ensure_bytes
import logging as logger

ANCHORE_ISSUER = "anchore-engine"
ANCHORE_AUDIENCE = "anchore-engine"
EXPIRATION_LEEWAY_SECONDS = 10
SUPPORTED_ALGORITHMS = ["HS256", "HS512", "RS256", "RS512"]

_token_manager = None


def is_enabled():
    """
    Returns true if oauth is enabled via configuration on this host and has a valid configuration (e.g. keys/secret is present)

    :return:
    """
    global _token_manager
    return _token_manager is None


def load_keys(config: dict):
    """
    Based on the passed configuration, load a dict mapping the key name to bytes of the key

    :param config: dict with specific keys to find keys, paths
    :return:
    """

    keys = {}

    if config:
        if config.get("private_key_path"):
            priv_keypath = config.get("private_key_path")
            try:
                with open(priv_keypath, "rb") as pem_fp:
                    keys["private"] = pem_fp.read()

            except IOError as e:
                raise Exception(
                    "Could not load private key file from path: {}. Error: {}".format(
                        priv_keypath, e
                    )
                )

        if config.get("public_key_path"):
            pub_keypath = config.get("public_key_path")
            try:
                with open(pub_keypath, "rb") as crt_fp:
                    keys["public"] = crt_fp.read()
            except IOError as e:
                raise Exception(
                    "Could not load public key file from path: {}. Error: {}".format(
                        pub_keypath, e
                    )
                )

        elif config.get("secret"):
            keys["secret"] = ensure_bytes(config.get("secret"))

    return keys


class TokenIssuer(object):
    """
    Creates oauth tokens signed by a specific private key
    """

    def __init__(self, key: bytes, alg: str, expiration: int, issuer=ANCHORE_ISSUER):
        assert alg in SUPPORTED_ALGORITHMS

        self.signing_key = key
        self.signing_alg = alg
        self.issuer = issuer
        self.expiration_seconds = expiration

    def generate_token(self, subject):
        """
        Return a tuple of the generated token and its expiration

        :param subject:
        :return:
        """

        if not self.signing_key:
            raise OauthNotConfiguredError("SP not configured")
        else:
            header = {"alg": self.signing_alg}
            ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

            expiration_ts = ts + datetime.timedelta(seconds=self.expiration_seconds)

            payload = {
                "iss": self.issuer,
                "sub": subject,
                "exp": expiration_ts,
                "iat": ts,
                "jti": uuid.uuid4().hex,
            }

            return (
                jwt.encode(header=header, payload=payload, key=self.signing_key),
                expiration_ts,
            )


class TokenVerifier(object):
    """
    Verify tokens with a given key
    """

    __claim_options__ = {"iss": {"essential": True}, "sub": {"essential": True}}

    __claim_params__ = {}

    def __init__(self, key: bytes, alg: str, issuers=None):
        if issuers is None:
            issuers = [ANCHORE_ISSUER]
        if alg not in SUPPORTED_ALGORITHMS:
            raise ValueError(alg)

        self.claim_options = copy.deepcopy(TokenVerifier.__claim_options__)
        self.claim_params = copy.deepcopy(TokenVerifier.__claim_params__)

        self.key = key
        self.alg = alg
        self.valid_issuers = issuers
        if self.valid_issuers:
            self.claim_options["iss"]["values"] = self.valid_issuers

    def verify_token(self, token: bytes) -> JWTClaims:
        claims = jwt.decode(
            s=token,
            key=self.key,
            claims_params=self.claim_params,
            claims_options=self.claim_options,
        )
        claims.validate()
        return claims


class JwtTokenManager(object):
    def __init__(self, oauth_config, keys_config):
        self.config = oauth_config
        self.keys_config = keys_config
        self._validate_config()

        self.keys = load_keys(keys_config)
        expiration = int(self.config.get("default_token_expiration_seconds"))
        self.issuers = {
            name: TokenIssuer(key, "RS256", expiration)
            if name != "secret"
            else TokenIssuer(key, "HS256", expiration, issuer=ANCHORE_ISSUER)
            for name, key in self.keys.items()
            if name in ["private", "secret"]
        }
        self.verifiers = {
            name: TokenVerifier(key, "RS256", issuers=[ANCHORE_ISSUER])
            if name != "secret"
            else TokenVerifier(key, "HS256")
            for name, key in self.keys.items()
            if name in ["public", "secret"]
        }

        if "public" in self.verifiers.keys():
            self._default_public = "public"
        else:
            self._default_public = "secret"

        if "private" in self.issuers.keys():
            self._default_private = "private"
        else:
            self._default_private = "secret"

    def _validate_config(self):
        logger.debug("Validating oauth config")
        if not self.config.get("enabled"):
            raise OauthNotConfiguredError("enabled = false")

        if self.config.get("default_token_expiration_seconds") is None:
            raise InvalidOauthConfigurationError(
                "default_token_expiration_seconds missing"
            )

        if type(self.config.get("default_token_expiration_seconds")) not in [
            int,
            float,
        ]:
            raise InvalidOauthConfigurationError(
                "default_token_expiration_seconds wrong type, must be integer"
            )

        if not self.keys_config:
            raise InvalidOauthConfigurationError("keys configuration required")

        if not self.keys_config.get("secret") and not (
            self.keys_config.get("private_key_path")
            and self.keys_config.get("public_key_path")
        ):
            raise InvalidOauthConfigurationError(
                'keys must have either "secret" set or both "public_key_path" and "private_key_path" set to valid pem files'
            )

        logger.debug("Oauth config ok")

    def generate_token(self, user_uuid, with_key_name=None, return_expiration=False):
        if not with_key_name:
            # If have priv key then use it, else use secret if available
            tok, exp = self.issuers[self._default_private].generate_token(user_uuid)
        else:
            tok, exp = self.issuers[with_key_name].generate_token(user_uuid)

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


def oauth_config_loader(config: dict):
    """
    Loads the key configuration from the default location

    :return:
    """
    assert config is not None
    return config.get("user_authentication", {}).get("oauth"), config.get("keys")


def token_manager(config=None):
    global _token_manager
    if _token_manager is None:
        if config is None:
            config = localconfig.get_config()

        assert config is not None
        oauth_config, keys_config = oauth_config_loader(config)
        _token_manager = JwtTokenManager(oauth_config, keys_config)

    return _token_manager
