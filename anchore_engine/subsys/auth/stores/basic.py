from yosai.core import account_abcs
from anchore_engine.db import session_scope, AccountTypes
from anchore_engine.subsys import logger
from anchore_engine.apis.authentication import idp_factory, IdentityContext
import json


class DbAccountStore(
    account_abcs.CredentialsAccountStore, account_abcs.AuthorizationAccountStore
):
    """
    Basic Anchore account management, uses the internal subsystem for accessing db objects.

    Very simple data model: Accounts -> Users. Exactly one account and user is the system admin.

    """

    SUPPORTED_CREDENTIAL_TYPE = "password"

    SYSTEM_ADMIN_PERMISSIONS = {
        # All permissions on all domains on all resources
        "*": json.dumps([{"domain": "*", "action": "*", "target": "*"}])
    }

    def _generate_user_permissions(self, account_name):
        # Read/write permissions within the account domain on everything except users/accounts
        return {
            account_name: json.dumps(
                [
                    {"domain": account_name, "action": "*", "target": "*"},
                ]
            )
        }

    def __init__(self, settings=None):
        self.settings = settings

    # CredentialAccountStore functions

    def _build_permissions_for(self, identity):
        if identity.user_account_type in [AccountTypes.admin, AccountTypes.service]:
            return self.SYSTEM_ADMIN_PERMISSIONS
        else:
            return self._generate_user_permissions(identity.user_account)

    def get_authc_info(self, identifier):
        """
        Function defined in the interface. Returns a dict:

        {
          'account_locked': bool,
          'authc_info': { '<str cred type>': { 'credential': <value>, 'failed_attempts': <int> } }
          'account_id': <str>
        }

        :param identifier:
        :return: populated dict defined above or empty structured dict above
        """

        result_account = {
            "account_locked": None,
            "authc_info": {},
            "account_id": None,
            "anchore_identity": None,  # Used to transmit more than just username
        }

        with session_scope() as db:
            idp = idp_factory.for_session(db)

            try:
                identity, creds = idp.lookup_user(identifier)
            except:
                logger.exception("Error looking up user")
                identity = None
                creds = None

            result_account["account_locked"] = False

            if identity:
                result_account["anchore_identity"] = identity

            if creds:
                result_account["authc_info"] = {
                    cred.type.value: {"credential": cred.value, "failed_attempts": []}
                    for cred in creds
                }

            return result_account

    # Authz AccountStore functions

    def get_authz_permissions(self, identifier):
        """
        Returns a dictionary mapping domain to permission parts.

        Dict is a map of:
        domain -> list of strings, each of which is a json-encoded dict: { 'domain': '...', 'action': '...', 'target': '...'}
        Example:
        {
        '*': [ '{"domain":"*", "action": "read", "target": "*"}', '{"domain":"*", "action": "write", "target": "something"}'],
        'users': [ '{"domain":"*", "action": "read", "target": "*"}', '{"domain":"*", "action": "write", "target": "blah"}']
        }

        Statically set to a single domain (*) and a single perm (*)

        :param identifier:
        :return: dict mapping a domain name to a list of permissions
        """
        with session_scope() as db:
            if isinstance(identifier, IdentityContext):
                # If already looked-up, use it
                identity = identifier
            else:
                # Lookup the user identity
                idp = idp_factory.for_session(db)
                identity, _ = idp.lookup_user(identifier)

            if identity:
                perms = self._build_permissions_for(identity)
                return perms
            else:
                return {}

    def get_authz_roles(self, identifier):
        """

        Returns a static list based on the user's account type

        :param identifier:
        :return: list of role names for the identifier
        """
        return []


class TokenAccountStore(DbAccountStore):
    """
    Basic Anchore account management, uses the internal subsystem for accessing db objects.

    Very simple data model: Accounts -> Users. Exactly one account and user is the system admin.

    """

    def get_authc_info(self, identifier):
        """
        Function defined in the interface. Returns a dict:

        {
          'account_locked': bool,
          'authc_info': { '<str cred type>': { 'credential': <value>, 'failed_attempts': <int> } }
          'account_id': <str>
        }

        This differs from the password-flow lookup in that it uses the users's uuid rather than username since tokens
        are tied to the uuid to ensure lifecycle tied to a specific instance of a username.

        :param identifier: the user's uuid as signed/encoded in the token
        :return: populated dict defined above or empty structured dict above
        """

        result_account = {
            "account_locked": None,
            "authc_info": {},
            "account_id": None,
            "anchore_identity": None,
        }

        with session_scope() as db:
            idp = idp_factory.for_session(db)

            try:
                identity, creds = idp.lookup_user_by_uuid(identifier)
            except:
                logger.exception("Error looking up user")
                identity = None
                creds = None

            result_account["account_locked"] = False
            if identity:
                result_account["anchore_identity"] = identity
                result_account["authc_info"]["jwt"] = {
                    "credential": identity.user_uuid,
                    "failed_attempts": [],
                }

            return result_account
