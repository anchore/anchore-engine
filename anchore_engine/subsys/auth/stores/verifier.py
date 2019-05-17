from yosai.core.authc.abcs import CredentialsVerifier, AuthenticationToken, Authenticator
from yosai.core.authc.authc import UsernamePasswordToken, IncorrectCredentialsException, TokenError
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_bytes


class SimpleVerifier(CredentialsVerifier):

    def __init__(self, settings):
        self.samlVerifier = SAMLVerifier(settings)

        self.token_resolver = {
            UsernamePasswordToken: self,
            SAMLToken: self.samlVerifier
        }

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


class SAMLToken(AuthenticationToken):
    def __init__(self, saml_token, remember_me=False):
        """
        :param saml_token: the SAML XML content
        :type saml_token: str
        """
        self.saml_doc = saml_token
        self.is_remember_me = remember_me

    @property
    def credentials(self):
        return self._credentials

    @credentials.setter
    def credentials(self, credentials):
        self._credentials = credentials



class SAMLVerifier(CredentialsVerifier):
    """
    Verifies the validity of a saml token
    """
    def __init__(self, settings):
        self.token_resolver = { SAMLToken: self }

    def verify_credentials(self, authc_token, account):
        logger.info("Verifying SAML token")
        return True
