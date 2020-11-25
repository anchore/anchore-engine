"""
API authentication functions and handlers for use in API processing

This is the interface exposed to services for identity.

"""
from collections import namedtuple

from anchore_engine.subsys.identities import manager_factory

IdentityContext = namedtuple(
    "IdentityContext",
    [
        "username",
        "user_account",
        "user_account_type",
        "user_account_state",
        "user_type",
        "user_uuid",
    ],
)
Credential = namedtuple("Credential", ["type", "value"])


class IdentityProvider(object):
    """
    Simple interface for read-only access to identities for use by api processing, e.g. not serving the actual user api.
    """

    def __init__(self, session=None):
        self.session = session
        self.mgr = manager_factory.for_session(session)

    def lookup_user(self, username):
        """
        Load the user and account for the given username, includes credentials and source account
        :param username:
        :return: (IdentityContext object, credential_list tuple)
        """
        usr = self.mgr.get_user(username)

        if usr:
            ident = IdentityContext(
                username=username,
                user_account=usr["account_name"],
                user_account_type=usr["account"]["type"],
                user_account_state=usr["account"]["state"],
                user_type=usr["type"],
                user_uuid=usr["uuid"],
            )
        else:
            # Handle the case where username doesn't match cleanly, rather than KeyError
            return None, None

        creds = [
            Credential(type=x[0], value=x[1]["value"])
            for x in usr.get("credentials", {}).items()
        ]

        return ident, creds

    def lookup_account(self, account):
        """
        Lookup an account only. Useful for context processing.

        :param account:
        :return:
        """
        return self.mgr.get_account(account)

    def lookup_user_by_uuid(self, user_uuid):
        """
        Load the user and account for the given uuid, same return type as lookup_account()

        :param username:
        :return: (IdentityContext object, credential_list tuple)
        """
        usr = self.mgr.get_user_by_uuid(user_uuid)

        if usr:
            ident = IdentityContext(
                username=usr["username"],
                user_account=usr["account_name"],
                user_account_type=usr["account"]["type"],
                user_account_state=usr["account"]["state"],
                user_type=usr["type"],
                user_uuid=usr["uuid"],
            )
        else:
            # Handle the case where username doesn't match cleanly, rather than KeyError
            return None, None

        creds = [
            Credential(type=x[0], value=x[1]["value"])
            for x in usr.get("credentials", {}).items()
        ]

        return ident, creds


class IdentityProviderFactory(object):
    def __init__(self, idp_cls):
        self.idp_cls = idp_cls

    def for_session(self, session):
        return self.idp_cls(session)


idp_factory = IdentityProviderFactory(IdentityProvider)
