"""
Authc/Authz interfaces for internal service communications, which differ from external user requests.
"""
#
# from yosai.core import authc_abcs, realm_abcs, authz_abcs
#
# class JwtToken(authc_abcs.AuthenticationToken):
#     def __init__(self, token):
#         self._jwt_token = token
#         self.principal = None
#         self.acting_as = None
#         self._decode()
#
#     def _decode(self):
#
#
#     @property
#     def credentials(self):
#         return self._jwt_decoded
#
#
#
# class JwtAuthenticator(authc_abcs.Authenticator):
#     def authenticate_account(self, authc_token):
#         pass
#
# class JwtVerifier(authc_abcs.CredentialsVerifier):
#     def verify_credentials(self, authc_token, account):
#         """
#         Note: this is different from the defined function, but matches the invoked function. (Diff is the 'self' arg)
#         :param authc_token:
#         :param account:
#         :return:
#         """
#         pass
#
#
# class InternalServiceRealm(realm_abcs.AuthorizingRealm, realm_abcs.AuthenticatingRealm):
#     """
#     Handler for all the internal service authc/authz using the internal service creds jwt mechanisms
#     """
#
#     def __init__(self):
#         pass
#
#     def authenticate_account(self, authc_token):
#         pass
#
#
#     def is_permitted(self, identifiers, permission_s):
#         pass
#
#
