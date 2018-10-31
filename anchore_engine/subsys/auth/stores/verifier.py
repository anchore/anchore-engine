from yosai.core.authc.abcs import CredentialsVerifier
from yosai.core.authc.authc import UsernamePasswordToken, IncorrectCredentialsException, TokenError
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_bytes


class SimpleVerifier(CredentialsVerifier):

    def __init__(self, settings):
        self.token_resolver = {UsernamePasswordToken: self}
        self.supported_tokens = self.token_resolver.keys()

    def verify_credentials(self, authc_token, authc_info):
        submitted = authc_token.credentials
        stored = self.get_stored_credentials(authc_token, authc_info)
        service = self.token_resolver[authc_token.__class__]

        try:
            if isinstance(authc_token, UsernamePasswordToken):
                result = service.verify(submitted, stored)
                if not result:
                    raise IncorrectCredentialsException

        except (ValueError, TokenError):
            raise IncorrectCredentialsException

    def verify(self, submitted, stored):
        return ensure_bytes(submitted) == ensure_bytes(stored)

    def get_stored_credentials(self, authc_token, authc_info):
        # look up the db credential type assigned to this type token:
        cred_type = authc_token.token_info['cred_type']

        try:
            return authc_info[cred_type]['credential']

        except KeyError:
            msg = "{0} is required but unavailable from authc_info".format(cred_type)
            raise KeyError(msg)
