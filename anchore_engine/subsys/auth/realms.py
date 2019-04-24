from yosai.core.realm.realm import AccountStoreRealm
from yosai.core.authz.authz import WildcardPermission, DefaultPermission
import rapidjson

from anchore_engine.db import AccountTypes
from anchore_engine.plugins.authorization.client import AuthzPluginHttpClient, Action
from anchore_engine.subsys import logger


class CaseSensitivePermission(DefaultPermission):
    def __init__(self, wildcard_string=None, parts=None, case_sensitive=True):
        # Replace constructor with code from the WildcardPermission constructor directly, but with parts init from DefaultPermission
        # This is necessary to get the case-sensitivity to init properly since the Default->Wildcard path messes it up
        self.case_sensitive = case_sensitive
        self.parts = {'domain': {'*'}, 'action': {'*'}, 'target': {'*'}}
        if wildcard_string:
            self.setparts(wildcard_string, case_sensitive)
        else:
            self.parts = {'domain': set([parts.get('domain', '*')]),
                          'action': set(parts.get('action', '*')),
                          'target': set(parts.get('target', '*'))}


class AnchoreNativeRealm(AccountStoreRealm):
    """
    Customized version of hte default AccountStoreRealm.

    This is required to get case-sensitive permission behavior, which is not supported by default.
    """

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
        identifier = identifiers.primary_identifier

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

    def get_authzd_permissions(self, identifier, perm_domain):
        """
        :type identifier:  str
        :type domain:  str

        :returns: a list of relevant DefaultPermission instances (permission_s)
        """
        permission_s = []
        related_perms = []
        keys = ['*', perm_domain]

        def query_permissions(self):
            msg = ("Could not obtain cached permissions for [{0}].  "
                   "Will try to acquire permissions from account store."
                   .format(identifier))
            logger.debug(msg)

            permissions = self.account_store.get_authz_permissions(identifier)
            if not permissions:
                msg = "Could not get permissions from account_store for {0}". \
                    format(identifier)
                raise ValueError(msg)
            return permissions

        try:
            msg2 = ("Attempting to get cached authz_info for [{0}]"
                    .format(identifier))
            logger.debug(msg2)

            domain = 'authorization:permissions:' + self.name

            related_perms = self.cache_handler. \
                hmget_or_create(domain=domain,
                                identifier=identifier,
                                keys=keys,
                                creator_func=query_permissions,
                                creator=self)
        except ValueError:
            msg3 = ("No permissions found for identifiers [{0}].  "
                    "Returning None.".format(identifier))
            logger.debug(msg3)

        except AttributeError:
            # this means the cache_handler isn't configured
            queried_permissions = query_permissions(self)

            related_perms = [queried_permissions.get('*'),
                             queried_permissions.get(perm_domain)]

        for perms in related_perms:
            # must account for None values:
            try:
                for parts in rapidjson.loads(perms):
                    permission_s.append(CaseSensitivePermission(parts=parts))
            except (TypeError, ValueError):
                pass

        return permission_s


class ExternalAuthzRealm(AnchoreNativeRealm):
    """
    A realm for doing external authz and internal authc

    __client__ is the intialized http client for requesting authorization
    __account_type_provider__ is a callable that takes a single parameter: username and returns the account type

    """
    __client__ = None
    __account_type_provider__ = None

    @classmethod
    def init_realm(cls, config, account_lookup_fn):
        logger.debug('Configuring realm with config: {}'.format(config))
        cls.__client__ = AuthzPluginHttpClient(url=config.get('endpoint'), verify_ssl=config.get('verify_ssl'))
        cls.__account_type_provider__ = account_lookup_fn

    def is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  SimpleRealmCollection
        """
        # If a service account or admin account user, use the default handler, not external calls
        if ExternalAuthzRealm.__account_type_provider__ and callable(ExternalAuthzRealm.__account_type_provider__) and \
                ExternalAuthzRealm.__account_type_provider__(identifiers.primary_identifier) in [AccountTypes.service, AccountTypes.admin]:
            logger.debug('Detected admin or service account, using internal authz')
            return super().is_permitted(identifiers, permission_s)

        result_list = [] # List of tuples (required_perm, is_permitted)
        identifier = identifiers.primary_identifier

        actions = {}
        for required_perm in permission_s:
            required_permission = CaseSensitivePermission(wildcard_string=required_perm)
            actions[Action(domain=','.join(required_permission.domain), action=','.join(required_permission.action), target=','.join(required_permission.target))] = required_perm

        if actions:
            try:
                resp = self.__client__.authorize(principal=identifier, action_s=list(actions.keys()))
                for i in resp.allowed:
                    result_list.append((actions[i], True))

                for i in resp.denied:
                    result_list.append((actions[i], False))
            except Exception as e:
                logger.exception('Unexpected error invoking authorization plugin via client: {}'.format(e))
                logger.error('Authorization plugin invocation error. Could not perform a proper authz check. Please check configuration and/or authz service status: {}'.format(self.__client__.url))
                raise e

        return result_list