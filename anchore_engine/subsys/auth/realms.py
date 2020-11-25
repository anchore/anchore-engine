from yosai.core.realm.realm import AccountStoreRealm
from yosai.core.authz.authz import DefaultPermission
from yosai.core.subject.identifier import SimpleIdentifierCollection
from yosai.core.exceptions import IncorrectCredentialsException

from anchore_engine.db import AccountTypes
from anchore_engine.plugins.authorization.client import AuthzPluginHttpClient, Action
from anchore_engine.apis.authentication import IdentityContext
from anchore_engine.subsys import logger
from anchore_engine.subsys.auth.stores.verifier import JwtToken


class CaseSensitivePermission(DefaultPermission):
    def __init__(self, wildcard_string=None, parts=None, case_sensitive=True):
        # Replace constructor with code from the WildcardPermission constructor directly, but with parts init from DefaultPermission
        # This is necessary to get the case-sensitivity to init properly since the Default->Wildcard path messes it up
        self.case_sensitive = case_sensitive
        self.parts = {"domain": {"*"}, "action": {"*"}, "target": {"*"}}
        if wildcard_string:
            self.setparts(wildcard_string, case_sensitive)
        else:
            self.parts = {
                "domain": set([parts.get("domain", "*")]),
                "action": set(parts.get("action", "*")),
                "target": set(parts.get("target", "*")),
            }


class UsernamePasswordRealm(AccountStoreRealm):
    """
    Anchore customized version of the default AccountStoreRealm from yosai.

    Uses a username/password db store.

    """

    __external_authorizer__ = None

    # --------------------------------------------------------------------------
    # Authentication
    # --------------------------------------------------------------------------

    def get_authentication_info(self, identifier):
        """
        The default authentication caching policy is to cache an account's
        credentials that are queried from an account store, for a specific
        user, so to facilitate any subsequent authentication attempts for
        that user. Naturally, in order to cache one must have a CacheHandler.
        If a user were to fail to authenticate, perhaps due to an
        incorrectly entered password, during the the next authentication
        attempt (of that user id) the cached account will be readily
        available from cache and used to match credentials, boosting
        performance.

        :returns: an Account object
        """
        account_info = None
        ch = self.cache_handler

        def query_authc_info(self):
            msg = (
                "Could not obtain cached credentials for [{0}].  "
                "Will try to acquire credentials from account store.".format(identifier)
            )
            logger.debug(msg)

            # account_info is a dict
            account_info = self.account_store.get_authc_info(identifier)

            if account_info is None:
                msg = "Could not get stored credentials for {0}".format(identifier)
                raise ValueError(msg)

            return account_info

        try:
            msg2 = "Attempting to get cached credentials for [{0}]".format(identifier)
            logger.debug(msg2)

            # account_info is a dict
            account_info = ch.get_or_create(
                domain="authentication:" + self.name,
                identifier=identifier,
                creator_func=query_authc_info,
                creator=self,
            )

        except AttributeError:
            # this means the cache_handler isn't configured
            account_info = query_authc_info(self)
        except ValueError:
            msg3 = (
                "No account credentials found for identifiers [{0}].  "
                "Returning None.".format(identifier)
            )
            logger.warn(msg3)

        if account_info:
            # Expect anchore to add the account_id already
            accnt_id = account_info.get("anchore_identity", identifier)
            account_info["account_id"] = SimpleIdentifierCollection(
                source_name=self.name, identifier=accnt_id
            )
        return account_info

    @staticmethod
    def _should_use_external(identity: IdentityContext):
        # # If a service account or admin account user, use the default handler, not external calls
        return identity.user_account_type not in [
            AccountTypes.service,
            AccountTypes.admin,
        ]

    def is_permitted(self, identifiers, permission_s):
        """
        If the authorization info cannot be obtained from the accountstore,
        permission check tuple yields False.

        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of one or more permissions, represented
                             as string-based permissions or Permission objects
                             and NEVER comingled types
        :type permission_s: list of string(s)

        :yields: tuple(Permission, Boolean)
        """

        logger.debug("Identifiers for is_permitted: {}".format(identifiers.__dict__))

        identifier = identifiers.primary_identifier

        if self.__external_authorizer__ and self._should_use_external(identifier):
            return self.__external_authorizer__.is_permitted(identifiers, permission_s)
        else:
            return self._check_internal_permitted(identifier, permission_s)

    def _check_internal_permitted(self, identifier, permission_s):
        """
        Do an internal perm check

        :param identifier:
        :param permission_s:
        :return:
        """
        for required_perm in permission_s:
            required_permission = CaseSensitivePermission(wildcard_string=required_perm)

            # get_authzd_permissions returns a list of DefaultPermission instances,
            # requesting from cache using '*' and permission.domain as hash keys:
            domain = next(iter(required_permission.domain))
            assigned_permission_s = self.get_authzd_permissions(identifier, domain)

            is_permitted = False
            for authorized_permission in assigned_permission_s:
                if authorized_permission.implies(required_permission):
                    is_permitted = True
                    break
            yield (required_perm, is_permitted)


class ExternalAuthorizer(object):
    """
    A realm for doing external authz and internal authc

    __client__ is the initialized http client for requesting authorization
    __account_type_provider__ is a callable that takes a single parameter: username and returns the account type

    """

    def __init__(self, config, enabled=False):
        logger.debug("Configuring realm with config: {}".format(config))
        self.enabled = enabled
        self.client = AuthzPluginHttpClient(
            url=config.get("endpoint"), verify_ssl=config.get("verify_ssl")
        )

    def is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  SimpleRealmCollection
        """
        # Fail all if not configured
        if not self.enabled or not self.client:
            return [(p, False) for p in permission_s]

        result_list = []  # List of tuples (required_perm, is_permitted)
        identifier = identifiers.primary_identifier
        if isinstance(identifier, IdentityContext):
            username = identifier.username
        else:
            username = identifier

        actions = {}
        for required_perm in permission_s:
            required_permission = CaseSensitivePermission(wildcard_string=required_perm)
            actions[
                Action(
                    domain=",".join(required_permission.domain),
                    action=",".join(required_permission.action),
                    target=",".join(required_permission.target),
                )
            ] = required_perm

        if actions:
            try:
                resp = self.client.authorize(
                    principal=username, action_s=list(actions.keys())
                )
                for i in resp.allowed:
                    result_list.append((actions[i], True))

                for i in resp.denied:
                    result_list.append((actions[i], False))
            except Exception as e:
                logger.exception(
                    "Unexpected error invoking authorization plugin via client: {}".format(
                        e
                    )
                )
                logger.error(
                    "Authorization plugin invocation error. Could not perform a proper authz check. Please check configuration and/or authz service status: {}".format(
                        self.client.url
                    )
                )
                raise e

        return result_list


class JwtRealm(UsernamePasswordRealm):
    """
    Customized version of the UsernamePassword realm but for interacting with a TokenStore

    """

    def authenticate_account(self, authc_token: JwtToken):
        try:
            assert authc_token.identifier is not None

            # Lookup the account info to verify the user identified by the token is still valid
            authc_info = self.get_authentication_info(authc_token.identifier)

            # Overwrite any creds found in db. Cleanup of token vs password is outside the scope of this handler.
            if not authc_info or not authc_info["authc_info"]:
                # No user exists for the identifier
                raise IncorrectCredentialsException
            else:
                return authc_info

        except:
            logger.debug_exception("Could not authenticate token")
            raise IncorrectCredentialsException()
