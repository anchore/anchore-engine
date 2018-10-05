from yosai.core.realm.realm import AccountStoreRealm
from yosai.core import DefaultPermission
from anchore_engine.plugins.authorization.client import AuthzPluginHttpClient, AuthorizationRequest, AuthorizationDecision, Action
from anchore_engine.subsys import logger


class ExternalAuthzRealm(AccountStoreRealm):
    """
    A realm for doing external authz and internal authc
    """
    __client__ = None

    @classmethod
    def init_realm(cls, config):
        logger.info('Configuring realm with config: {}'.format(config))

        cls.__client__ = AuthzPluginHttpClient(url=config.get('endpoint'), verify_ssl=config.get('verify_ssl'))

    def get_authzd_permissions(self, identitier, domain):
        """
        Not used in this impl
        :param identitier:
        :param domain:
        :return:
        """
        return []

    def get_authzd_roles(self, identitier):
        """
        Not used in this impl
        :param identitier:
        :return:
        """
        return []

    def is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  SimpleRealmCollection
        """
        result_list = [] # List of tuples (required_perm, is_permitted)

        identifier = identifiers.primary_identifier

        actions = {}
        for required_perm in permission_s:
            required_permission = DefaultPermission(wildcard_string=required_perm)
            actions[Action(domain=required_permission.domain, action=required_permission.action, target=required_permission.target)] = required_perm

        try:
            resp = self.__client__.authorize(principal=identifier, action_s=list(actions.keys()))
            for i in resp.allowed:
                result_list.append((actions[i], True))

            for i in resp.denied:
                result_list.append((actions[i], False))

        except Exception as e:
            logger.exception('Unexpected error invoking authorization plugin via client: {}'.format(e))
            raise e

        return result_list
