from yosai.core.realm.realm import AccountStoreRealm
from yosai.core import DefaultPermission
from anchore_engine.plugins.authorization.client import AuthzPluginHttpClient, Action
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import AccountTypes


class ExternalAuthzRealm(AccountStoreRealm):
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
            required_permission = DefaultPermission(wildcard_string=required_perm)
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
