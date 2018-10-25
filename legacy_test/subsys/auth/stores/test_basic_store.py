import json
import unittest
from anchore_engine.db import session_scope
from anchore_engine.subsys import identities
from anchore_engine.subsys.identities import AccountTypes, UserAccessCredentialTypes
from anchore_engine.subsys.auth.stores import basic as basic_accountstore
from yosai.core import UsernamePasswordToken, DefaultPermission
from passlib.context import CryptContext


class TestBasicStore(unittest.TestCase):
    """
    Tests for the auth subsys
    Identities etc.

    """

    @classmethod
    def setup_engine_config(cls, db_connect_str):
        """
        Sets the config for the service to bootstrap a specific db.
        :param db_connect_str:
        :return:
        """
        from anchore_engine.configuration import localconfig
        localconfig.load_defaults()
        localconfig.localconfig['credentials'] = {
            'database': {
                'db_connect': db_connect_str
            }
        }
        return localconfig.localconfig

    @classmethod
    def init_db(cls, connect_str='sqlite:///:memory:', do_bootstrap=True):
        """
        Policy-Engine specific db initialization and setup for testing.

        :param connect_str: connection string, defaults to sqllite in-memory if none provided
        :return:

        """
        conf = cls.setup_engine_config(connect_str)
        from anchore_engine.db import initialize, Account, AccountUser, AccessCredential, Anchore
        from anchore_engine.db.entities.common import do_create
        from anchore_engine.version import version, db_version
        initialize(versions={'service_version': version, 'db_version': db_version}, localconfig=conf)
        do_create(specific_tables=[Account.__table__, AccountUser.__table__, AccessCredential.__table__, Anchore.__table__])


    @classmethod
    def setUpClass(cls):
        cls.init_db()

    #
    # def tearDown(self):
    #     for accnt in identities.list_accounts():
    #         print('Deleting accnt: {}'.format(accnt))
    #         identities.delete_account(accnt['name'])

    def test_account_store(self):
        cc = CryptContext(schemes=['argon2'])

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            accnt = mgr.create_account(account_name='account1', account_type=AccountTypes.user, email='someemail')
            user1 = mgr.create_user(account_name=accnt['name'], username='testuser1',
                                           password='password123')
            print('user 1: {}'.format(user1))

            user2 = mgr.create_user(account_name=accnt['name'], username='testuser2',
                                           password='password123')
            print('user 2: {}'.format(user2))

            accnt2 = mgr.create_account(account_name='admin1', account_type=AccountTypes.admin, email='someemail',)
            user3 = mgr.create_user(account_name=accnt2['name'], username='admin1', password='password123')
            print('user 3: {}'.format(user3))

        store = basic_accountstore.DbAccountStore()

        # Authc stuff
        token = UsernamePasswordToken(username='testuser1',
                                      password=user1['credentials'][UserAccessCredentialTypes.password]['value'])
        print(token.credentials)
        resp = store.get_authc_info(token.identifier)
        print(resp)
        self.assertTrue(cc.verify(token.credentials, resp['authc_info']['password']['credential']))

        # Authz stuff
        authz_resp = store.get_authz_permissions(token.identifier)
        print(authz_resp)

        # Standard user
        self.assertTrue(DefaultPermission(parts=json.loads(authz_resp[user1['account_name']])[0]).implies(DefaultPermission(parts={'domain': user1['account_name'], 'action': '*', 'target': '*'})))
        self.assertIsNone(authz_resp.get('*'))

        admin_token = UsernamePasswordToken(username='admin1',
                                      password=user3['credentials'][UserAccessCredentialTypes.password]['value'])
        # Authz stuff
        authz_resp = store.get_authz_permissions(admin_token.identifier)
        print(authz_resp)

        # Admin user
        self.assertIsNotNone(authz_resp.get('*'))
        self.assertIsNone(authz_resp.get(user3['account_name']))
        self.assertTrue(DefaultPermission(parts=json.loads(authz_resp['*'])[0]).implies(DefaultPermission(parts={'domain': '*', 'action': '*', 'target': '*'})))




