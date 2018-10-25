import re
import anchore_engine.configuration
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.db import db_accounts, db_account_users, AccountTypes, UserAccessCredentialTypes, AccountStates
from anchore_engine.db.db_accounts import AccountNotFoundError

# Not currently used because upgrade...
name_validator_regex = re.compile('^[a-z0-9][a-z0-9_-]{1,126}[a-z0-9]$')
email_validator_regex = re.compile("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
password_validator_regex = re.compile('.{6,128}$')


class IdentityBootstrapper(object):
    def __init__(self, identity_manager_cls, session):
        self.mgr = identity_manager_cls(session)
        self.session = session

    def initialize_system_identities(self):
        """
        Ensure basic system identities are present
        :param session: DB session to use to query/update. Tx managed externally
        :return: boolean status
        """

        # system user
        try:

            if not self.mgr.get_account(localconfig.SYSTEM_ACCOUNT_NAME):
                self.mgr.create_account(localconfig.SYSTEM_ACCOUNT_NAME, AccountTypes.service, 'system@system')

            if not self.mgr.get_user(localconfig.SYSTEM_USERNAME):
                self.mgr.create_user(localconfig.SYSTEM_ACCOUNT_NAME, localconfig.SYSTEM_USERNAME)
                self.mgr.add_user_credential(username=localconfig.SYSTEM_USERNAME, credential_type=UserAccessCredentialTypes.password)

        except Exception as err:
            logger.exception('Error initializing system identities')
            raise Exception(
                "Initialization failed: could not fetch/add anchore-system user from/to DB - exception: " + str(err))

        # admin user
        try:
            if not self.mgr.get_account(localconfig.ADMIN_ACCOUNT_NAME):
                init_email = localconfig.get_config().get(localconfig.DEFAULT_ADMIN_EMAIL_KEY, 'admin@myanchore')
                self.mgr.create_account(localconfig.ADMIN_ACCOUNT_NAME, AccountTypes.admin, init_email)

            if not self.mgr.get_user(localconfig.ADMIN_USERNAME):
                self.mgr.create_user(localconfig.ADMIN_ACCOUNT_NAME, localconfig.ADMIN_USERNAME)

                init_password = localconfig.get_config().get(localconfig.DEFAULT_ADMIN_PASSWORD_KEY, localconfig.ADMIN_USER_DEFAULT_PASSWORD)
                self.mgr.add_user_credential(username=localconfig.ADMIN_USERNAME,
                                             credential_type=UserAccessCredentialTypes.password,
                                             value=init_password)

            return True
        except Exception as err:
            logger.exception('Error initializing system identities')
            raise Exception(
                "Initialization failed: could not fetch/add anchore-system user from/to DB - exception: " + str(
                    err))

    def initialize_user_identities_from_config(self, config_credentials):
        """
        Support for the older credential configs in the config.yaml to load them into the db.

        Default behavior is to create an account and user with same id for each entry in the config.

        :param config_credentials: the 'credentials' section of the configuration
        :return:
        """

        try:
            if 'users' not in config_credentials:
                # Nothing to do
                return

            for userId, user_config in config_credentials['users'].items():
                if not user_config:
                    logger.warn(
                        'Found empty entry for userId {} in config file. Skipping initialization.'.format(userId))
                    continue

                if userId == localconfig.ADMIN_USERNAME:
                    user_type = AccountTypes.admin
                else:
                    user_type = AccountTypes.user

                password = user_config.pop('password', None)
                email = user_config.pop('email', None)
                if password and email:
                    try:
                        account = self.mgr.create_account(userId, account_type=user_type, email=email)
                    except db_accounts.AccountAlreadyExistsError:
                        pass
                    except:
                        logger.exception('Error initializing account: {}'.format(userId))
                        raise

                    try:
                        self.mgr.create_user(account_name=userId, username=userId, password=password)
                    except db_account_users.UserAlreadyExistsError:
                        pass
                    except:
                        logger.exception('Error initializing user: {}'.format(userId))
                        raise

                else:
                    raise Exception("user defined but has empty password/email: " + str(userId))
        except Exception as err:
            logger.exception('Error initializing users')
            raise Exception("Initialization failed: could not add users from config into DB - exception: " + str(err))


class IdentityManagerFactory(object):
    def __init__(self, configuration=None):
        self.configuration = configuration

    @classmethod
    def for_session(cls, session):
        return IdentityManager(session)


manager_factory = IdentityManagerFactory(localconfig.get_config())

class IdentityManager(object):
    """
    A db session-aware identity manager.
    """

    def __init__(self, session):
        """
        :param session:
        """
        self.session = session

    def _get_system_user_credentials(self):
        rec = db_accounts.get(localconfig.SYSTEM_USERNAME, session=self.session)
        if rec:
            cred = db_account_users.get(localconfig.SYSTEM_USERNAME, session=self.session)
            return cred['username'], cred.get('credentials', {}).get(UserAccessCredentialTypes.password, {}).get(
                'value')
        else:

            return None, None

    def get_system_credentials(self):
        """
        Get system credentials, from the local cache if available first
        :return: (username, password) tuple
        """

        localconfig = anchore_engine.configuration.localconfig.get_config()
        if 'system_user_auth' in localconfig and localconfig['system_user_auth'] != (None, None):
            return localconfig['system_user_auth']
        else:
            return self._get_system_user_credentials()

    def get_credentials_for_userid(self, userId):
        """
        Return any credential for the userid (account name, for legacy support)

        :param userId:
        :param self.session:
        :return:
        """

        usrs = db_account_users.list_for_account(userId, session=self.session)
        if usrs:
            return usrs[0]['username'], usrs[0].get('credentials', {}).get(UserAccessCredentialTypes.password, {}).get(
                'value')
        else:
            return None, None

    def get_credentials_for_username(self, username):
        user = db_account_users.get(username=username, session=self.session)
        return user['username'], user.get('credentials', {}).get(UserAccessCredentialTypes.password, {}).get('value')

    def create_account(self, account_name, account_type, email):
        """
        Creates a new account in a unit-of-work (transaction). Creates an account_name_admin' user as well with an autogenerated password

        :param account_name:
        :param account_type:
        :param email:
        :return: (account, user) tuple with the account and admin user for the account
        """
        account = db_accounts.add(account_name, account_type=account_type, email=email, state=AccountStates.enabled, session=self.session)
        return account

    def list_accounts(self, with_state=None, include_service=False):
        accounts = filter(lambda x: (include_service or (x['type'] != AccountTypes.service)),
                          db_accounts.get_all(with_state=with_state, session=self.session))
        return accounts

    def get_account(self, accountname):
        account = db_accounts.get(accountname, session=self.session)
        return account

    def update_account_state(self, account_name: str, new_state: AccountStates):
        return db_accounts.update_state(account_name, new_state, session=self.session)

    def delete_account(self, account_name):
        return db_accounts.delete(account_name, session=self.session)

    def create_user(self, account_name, username, password=None):
        """
        Create a new user as a unit-of-work (e.g. a single db transaction

        :param account_name:
        :param username:
        :param access_type:
        :return:
        """

        account = db_accounts.get(account_name, session=self.session)
        if not account:
            raise AccountNotFoundError('Account does not exist')

        usr_record = db_account_users.add(account_name=account_name, username=username,
                                          session=self.session)

        if password is not None:
            db_account_users.add_user_credential(username=username,
                                                 credential_type=UserAccessCredentialTypes.password, value=password,
                                                 session=self.session)
            usr_record = db_account_users.get(username, session=self.session)

        return usr_record

    def delete_user(self, username):
        return db_account_users.delete(username, session=self.session)

    def get_user(self, username):
        return db_account_users.get(username, session=self.session)

    def list_users(self, account_name=None):
        if account_name:

            return db_account_users.list_for_account(account_name, session=self.session)
        else:
            return db_account_users.get_all(session=self.session)

    def add_user_credential(self, username, credential_type, value=None, overrwite=True):
        """
        Add a new password to a user

        :param username:
        :param credential_type: UserAccessCredentialType
        :param value: str value to set, may be None and if password, one will be generated
        :return:
        """
        credential = db_account_users.add_user_credential(username=username,
                                                          credential_type=credential_type, value=value,
                                                          session=self.session)
        return credential

    def delete_user_credential(self, username, cred_type):
        return db_account_users.delete_user_credential(username, credential_type=cred_type, session=self.session)
