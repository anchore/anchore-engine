import unittest
from anchore_engine.db import session_scope, AccountTypes, UserAccessCredentialTypes
from anchore_engine.subsys import identities


class TestIdentities(unittest.TestCase):
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
        from anchore_engine.db import initialize, Account, AccountUser, AccessCredential, Anchore, PolicyBundle
        from anchore_engine.db.entities.common import do_create
        from anchore_engine.version import version, db_version
        initialize(versions={'service_version': version, 'db_version': db_version}, localconfig=conf)
        do_create(specific_tables=[Account.__table__, AccountUser.__table__, AccessCredential.__table__, Anchore.__table__, PolicyBundle.__table__])


    @classmethod
    def setUpClass(cls):
        cls.init_db()

    def tearDown(self):
        for accnt in identities.list_accounts():
            print('Deleting accnt: {}'.format(accnt))
            identities.delete_account(accnt['name'])

    def test_initialize_identities(self):
        with session_scope() as session:
            identities.initialize_system_identities(session=session)

        accnt1 = identities.get_account(identities.system_username)
        print(accnt1)
        self.assertEqual(AccountTypes.service, accnt1['type'])

        with session_scope() as session:
            user1, creds1 = identities.get_credentials_for_username(session, identities.system_username)
        print(creds1)
        self.assertIsNotNone(user1)
        self.assertIsNotNone(creds1)
        self.assertEquals(UserAccessCredentialTypes.password, creds1)

    def test_initialize_users(self):
        test_creds = {
            'users': {
                'user1': {
                    'password': 'abc123',
                    'email': 'user1@email'
                },
                'user2': {
                    'password': 'def466',
                    'email': 'user2@email'
                }
            }
        }

        with session_scope() as session:
            identities.initialize_user_identities_from_config(session, config_credentials=test_creds)

        accnt1 = identities.get_account('user1')
        print(accnt1)
        self.assertIsNotNone(accnt1)
        with session_scope() as session:
            user1, cred1 = identities.get_credentials_for_username(session, 'user1')
        print(cred1)
        self.assertIsNotNone(cred1)

        accnt2 = identities.get_account('user2')
        print(accnt2)
        self.assertIsNotNone(accnt2)
        with session_scope() as session:
            user2, cred2 = identities.get_credentials_for_username(session, 'user2')
        print(cred2)
        self.assertIsNotNone(cred2)

    def test_create(self):
        print('Creating user account/users')
        fixtures = [
            ('user_account1', 'user1', AccountTypes.user),
            ('admin_account1', 'user2', AccountTypes.admin),
            ('system_account1', 'user3', AccountTypes.user)
        ]

        for account_name, user_name, account_type in fixtures:
            identities.create_account(account_name=account_name, account_type=account_type, creator='test0', email='blah')
            accnt = identities.get_account(account_name)
            self.assertIsNotNone(accnt)
            self.assertEqual(account_type, accnt['type'])

            identities.create_user(username=user_name, account_name=account_name, creator_name='test0', password='password123')
            usr = identities.get_user(user_name)
            self.assertIsNotNone(usr)
            self.assertEqual(account_name, usr['account_name'])


