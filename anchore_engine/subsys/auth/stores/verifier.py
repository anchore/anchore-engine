import time
from yosai.core.authc.abcs import CredentialsVerifier
from yosai.core.authc.authc import (
    UsernamePasswordToken,
    IncorrectCredentialsException,
    TokenError,
    PasslibVerifier,
)
from yosai.core.authc.abcs import AuthenticationToken
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_bytes
from anchore_engine.auth.oauth import token_manager
from anchore_engine.configuration import localconfig


class ConfigurableVerifier(CredentialsVerifier):
    def __init__(self, settings):
        self.simple = SimplePasswordVerifier(settings)
        self.passlib_verify = PasslibVerifier(settings)
        self.supported_tokens = [UsernamePasswordToken]

    def verify_credentials(self, authc_token, account):
        if (
            localconfig.get_config()
            .get("user_authentication", {})
            .get("hashed_passwords")
        ):
            return self.passlib_verify.verify_credentials(authc_token, account)
        else:
            return self.simple.verify_credentials(authc_token, account)


class SimplePasswordVerifier(CredentialsVerifier):
    def __init__(self, settings):
        self.token_resolver = {UsernamePasswordToken: self}
        self.supported_tokens = self.token_resolver.keys()

    def verify_credentials(self, authc_token, authc_info):
        submitted = authc_token.credentials

        try:
            if isinstance(authc_token, UsernamePasswordToken):
                service = self.token_resolver[authc_token.__class__]
                stored = self.get_stored_credentials(authc_token, authc_info)

                if stored is None:
                    # No credential to check, cannot verify
                    raise IncorrectCredentialsException

                result = service.verify(submitted, stored)
                if not result:
                    raise IncorrectCredentialsException
            else:
                logger.debug("Incorrect credential type for password verifier")
                raise IncorrectCredentialsException

        except TokenError as e:
            logger.debug("TokenError in password verifier")
            raise IncorrectCredentialsException

    def verify(self, submitted, stored):
        return ensure_bytes(submitted) == ensure_bytes(stored)

    def get_stored_credentials(self, authc_token, authc_info):
        # look up the db credential type assigned to this type token:
        cred_type = authc_token.token_info["cred_type"]
        try:
            return authc_info[cred_type]["credential"]
        except KeyError:
            logger.debug(
                "{0} is required but unavailable from authc_info: {1}, {2}".format(
                    cred_type, authc_info, authc_token
                )
            )
            return None


class JwtToken(AuthenticationToken):
    """
    Token class with verification built-in by the factory.
    To customize the factory set the __factory__ property on the object or class

    By default, tokens must be validated with a signature. To disable that behavior,
    change the __require_validated_tokens__ to false.

    """

    __factory__ = token_manager
    __require_validated_tokens = True

    def __init__(self, token):
        self._token = token
        self.token_info = None
        self._verified = False
        self._identifier = None
        self._claims = None

        try:
            self._parse()
        except:
            logger.debug_exception("Error parsing/verifying token")
            self._identifier = None
            self._verified = False
            self._claims = None

    def _parse(self):
        """
        Verify the token content. If not verified
        :return:
        """
        verifier = JwtToken.__factory__()
        self._claims = verifier.verify_token(self._token)
        self._verified = True
        self._identifier = self._claims.get("sub", None)

    @property
    def credentials(self):
        """
        Returns the credentials submitted by the user during the authentication
        process that verifies the submitted Identifier account identity.
        """

        return self._token

    @property
    def identifier(self):
        return self._identifier

    def __str__(self):
        return "<JwtToken token={},token_info={}>".format(self._token, self.token_info)

    @property
    def user_id(self):
        return self._identifier

    @property
    def revoked(self):
        # TODO: impl this
        return False

    def get_expires_at(self):
        """
        Returns the expiration as a time.time float
        :return:
        """
        return self._claims["exp"]

    def is_expired(self):
        return self.get_expires_at() < time.time()


class BearerTokenVerifier(CredentialsVerifier):
    """
    Verify a Bearer token using authlib
    """

    def __init__(self, settings):
        self.config = settings
        self.token_resolver = {JwtToken: self}
        self._supported_tokens = set(self.token_resolver.keys())

    @property
    def supported_tokens(self):
        return self._supported_tokens

    def verify_credentials(self, authc_token, authc_info):
        logger.debug("Verifying bearer token")

        if isinstance(authc_token, JwtToken):
            # For a token the 'credentials' part is the uuid of the user
            if (
                not authc_token.identifier
                or authc_token.is_expired()
                or authc_token.identifier
                != authc_info.get("authc_info", {}).get("jwt", {}).get("credential")
            ):
                raise IncorrectCredentialsException
        else:
            logger.debug("Wrong type for bearer verify")
            raise IncorrectCredentialsException
