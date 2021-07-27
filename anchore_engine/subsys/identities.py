import datetime
import re
from threading import RLock

from anchore_engine.auth.oauth import OauthNotConfiguredError, token_manager
from anchore_engine.configuration import localconfig
from anchore_engine.db import (
    AccountStates,
    AccountTypes,
    UserAccessCredentialTypes,
    UserTypes,
    db_account_users,
    db_accounts,
)
from anchore_engine.db.db_accounts import AccountNotFoundError
from anchore_engine.subsys import logger
from anchore_engine.subsys.caching import TTLCache

# Not currently used because upgrade...
name_validator_regex = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9@.!#$+-=^_`~;]{1,126}[a-zA-Z0-9]$"
)
email_validator_regex = re.compile(
    r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)
password_validator_regex = re.compile(".{6,128}$")


def is_valid_username(candidate):
    """
    Check the candidate for validity against the acceptance for user names

    :param candidate:
    :return:
    """

    return name_validator_regex.match(candidate) is not None


def is_valid_accountname(candidate):
    """
    Check the candidate for validity against the acceptance for account names
    :param candidate:
    :return:
    """

    return is_valid_username(candidate)


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
                self.mgr.create_account(
                    localconfig.SYSTEM_ACCOUNT_NAME,
                    AccountTypes.service,
                    "system@system",
                )

            if not self.mgr.get_user(localconfig.SYSTEM_USERNAME):
                self.mgr.create_user(
                    localconfig.SYSTEM_ACCOUNT_NAME, localconfig.SYSTEM_USERNAME
                )
                self.mgr.add_user_credential(
                    username=localconfig.SYSTEM_USERNAME,
                    credential_type=UserAccessCredentialTypes.password,
                )

        except Exception as err:
            logger.exception("Error initializing system identities")
            raise Exception(
                "Initialization failed: could not fetch/add anchore-system user from/to DB - exception: "
                + str(err)
            )

        # admin user
        try:
            if not self.mgr.get_account(localconfig.ADMIN_ACCOUNT_NAME):
                init_email = localconfig.get_config().get(
                    localconfig.DEFAULT_ADMIN_EMAIL_KEY, "admin@myanchore"
                )
                self.mgr.create_account(
                    localconfig.ADMIN_ACCOUNT_NAME, AccountTypes.admin, init_email
                )

            if not self.mgr.get_user(localconfig.ADMIN_USERNAME):
                self.mgr.create_user(
                    localconfig.ADMIN_ACCOUNT_NAME, localconfig.ADMIN_USERNAME
                )

                init_password = localconfig.get_config().get(
                    localconfig.DEFAULT_ADMIN_PASSWORD_KEY,
                )

                if not init_password:
                    raise Exception("No default admin password provided")

                self.mgr.add_user_credential(
                    username=localconfig.ADMIN_USERNAME,
                    credential_type=UserAccessCredentialTypes.password,
                    value=init_password,
                )
            return True
        except Exception as err:
            logger.exception("Error initializing system identities")
            raise Exception(
                "Initialization failed: could not fetch/add anchore-system user from/to DB - exception: "
                + str(err)
            )

    def initialize_user_identities_from_config(self, config_credentials):
        """
        Support for the older credential configs in the config.yaml to load them into the db.

        Default behavior is to create an account and user with same id for each entry in the config.

        :param config_credentials: the 'credentials' section of the configuration
        :return:
        """

        logger.info("Initializing user identities from config")

        try:
            if "users" not in config_credentials:
                # Nothing to do
                return

            for userId, user_config in config_credentials["users"].items():
                if not user_config:
                    logger.warn(
                        "Found empty entry for userId {} in config file. Skipping initialization.".format(
                            userId
                        )
                    )
                    continue

                if userId == localconfig.ADMIN_USERNAME:
                    user_type = AccountTypes.admin
                else:
                    user_type = AccountTypes.user

                password = user_config.pop("password", None)
                email = user_config.pop("email", None)
                if password and email:
                    try:
                        account = self.mgr.create_account(
                            userId, account_type=user_type, email=email
                        )
                    except db_accounts.AccountAlreadyExistsError:
                        pass
                    except:
                        logger.exception(
                            "Error initializing account: {}".format(userId)
                        )
                        raise

                    try:
                        self.mgr.create_user(
                            account_name=userId, username=userId, password=password
                        )
                    except db_account_users.UserAlreadyExistsError:
                        pass
                    except:
                        logger.exception("Error initializing user: {}".format(userId))
                        raise

                else:
                    raise Exception(
                        "user defined but has empty password/email: " + str(userId)
                    )
        except Exception as err:
            logger.exception("Error initializing users")
            raise Exception(
                "Initialization failed: could not add users from config into DB - exception: "
                + str(err)
            )


class IdentityManagerFactory(object):
    def __init__(self, configuration=None):
        self.configuration = configuration

    @classmethod
    def for_session(cls, session):
        return IdentityManager(session)


manager_factory = IdentityManagerFactory(localconfig.get_config())


class AccessCredential(object):
    def get_creds(self):
        pass

    def is_expired(self):
        pass


class HttpBasicCredential(AccessCredential):
    def __init__(self, username, password):
        self.user = username
        self.password = password

    def get_creds(self):
        return self.user, self.password

    def is_expired(self):
        return False


class HttpBearerCredential(AccessCredential):
    def __init__(self, token: str, expiration: datetime.datetime = None):
        self.token = token
        self.expires_at = expiration

    def is_expired(self):
        dt = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        return self.expires_at is not None and dt >= self.expires_at

    def get_creds(self):
        return self.token


class IdentityManager(object):
    """
    A db session-aware identity manager.
    """

    _cache_lock = RLock()
    _credential_cache = TTLCache(default_ttl_sec=-1)
    _cache_lock_wait = localconfig.CRED_CACHE_LOCK_WAIT_SEC

    def __init__(self, session):
        """
        :param session:
        """
        self.session = session

    def _get_system_user_credentials(self):
        """
        Returns an AccessCredential object representing the system user

        :return:
        """
        cred = None
        exp = None  # Credential expiration, if needed

        logger.debug("Loading system user creds")

        with IdentityManager._cache_lock:
            cached_cred = IdentityManager._credential_cache.lookup(
                localconfig.SYSTEM_USERNAME
            )

            if cached_cred is not None:
                if cached_cred.is_expired():
                    # Flush it
                    logger.debug("Cached system credential is expired, flushing")
                    IdentityManager._credential_cache.delete(
                        localconfig.SYSTEM_USERNAME
                    )
                else:
                    logger.debug("Cached system credential still ok")
                    # Use it
                    cred = cached_cred

            if cred is None:
                logger.debug("Doing refresh/initial system cred load")

                try:
                    tok_mgr = token_manager()
                except OauthNotConfiguredError:
                    tok_mgr = None

                # Generate one
                if tok_mgr:
                    # Generate a token
                    usr = db_account_users.get(
                        localconfig.SYSTEM_USERNAME, session=self.session
                    )
                    system_user_uuid = usr["uuid"]
                    tok, exp = tok_mgr.generate_token(
                        system_user_uuid, return_expiration=True
                    )
                    logger.debug("Generated token with expiration {}".format(exp))
                    cred = HttpBearerCredential(tok, exp)
                else:
                    rec = db_accounts.get(
                        localconfig.SYSTEM_USERNAME, session=self.session
                    )
                    usr = db_account_users.get(
                        localconfig.SYSTEM_USERNAME, session=self.session
                    )

                    if not rec or not usr:
                        logger.error(
                            "Could not find a system account or user. This is not an expected state"
                        )
                        raise Exception("No system account or user found")

                    # This will not work if the system admin has configured hashed passwords but not oauth. But, that should be caught at config validation.
                    cred = HttpBasicCredential(
                        usr["username"],
                        usr.get("credentials", {})
                        .get(UserAccessCredentialTypes.password, {})
                        .get("value"),
                    )

                if cred is not None:
                    logger.debug("Caching system creds")
                    IdentityManager._credential_cache.cache_it(
                        localconfig.SYSTEM_USERNAME, cred
                    )

        return cred

    def get_system_credentials(self):
        """
        Get system credentials, from the local cache if available first
        :return: (username, password) tuple
        """
        lc = localconfig.get_config()
        if "system_user_auth" in lc and lc["system_user_auth"] != (None, None):
            creds = lc["system_user_auth"]
            logger.debug("Using creds found in config: {}".format(creds))

            if type(creds) in [tuple, list]:
                return HttpBasicCredential(creds[0], creds[1])
            elif type(creds) == str:
                # Assume its a bearer token
                return HttpBearerCredential(token=creds, expiration=None)
            else:
                return creds

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
            return (
                usrs[0]["username"],
                usrs[0]
                .get("credentials", {})
                .get(UserAccessCredentialTypes.password, {})
                .get("value"),
            )
        else:
            return None, None

    def get_credentials_for_username(self, username):
        user = db_account_users.get(username=username, session=self.session)
        return (
            user["username"],
            user.get("credentials", {})
            .get(UserAccessCredentialTypes.password, {})
            .get("value"),
        )

    def create_account(self, account_name, account_type, email):
        """
        Creates a new account in a unit-of-work (transaction). Creates an account_name_admin' user as well with an autogenerated password

        :param account_name:
        :param account_type:
        :param email:
        :return: (account, user) tuple with the account and admin user for the account
        """
        if not is_valid_accountname(account_name):
            raise ValueError(
                "Account name must match regex {}".format(name_validator_regex)
            )

        account = db_accounts.add(
            account_name,
            account_type=account_type,
            email=email,
            state=AccountStates.enabled,
            session=self.session,
        )
        return account

    def list_accounts(self, with_state=None, include_service=False):
        accounts = list(
            filter(
                lambda x: (include_service or (x["type"] != AccountTypes.service)),
                db_accounts.get_all(with_state=with_state, session=self.session),
            )
        )
        return accounts

    def get_account(self, accountname):
        account = db_accounts.get(accountname, session=self.session)
        return account

    def update_account_state(self, account_name: str, new_state: AccountStates):
        return db_accounts.update_state(account_name, new_state, session=self.session)

    def delete_account(self, account_name):
        return db_accounts.delete(account_name, session=self.session)

    def create_user(
        self,
        account_name,
        username,
        password=None,
        user_type=UserTypes.native,
        user_source=None,
    ):
        """
                Create a new user as a unit-of-work (e.g. a single db transaction

                :param account_name: the str account name
                :param username: the str username
                :param password: the password to set
                :param user_type: The type of user to create
        a        :return:
        """
        if not is_valid_username(username):
            raise ValueError(
                "username must match regex {}".format(name_validator_regex)
            )

        if user_type in [UserTypes.external] and password is not None:
            raise AssertionError("Cannot set password for external user type")

        if user_type == UserTypes.external and user_source is None:
            raise ValueError("user_source cannot be None with user_type = external")

        account = db_accounts.get(account_name, session=self.session)
        if not account:
            raise AccountNotFoundError("Account does not exist")

        usr_record = db_account_users.add(
            account_name=account_name,
            username=username,
            user_type=user_type,
            user_source=user_source,
            session=self.session,
        )

        if password is not None:
            db_account_users.add_user_credential(
                username=username,
                credential_type=UserAccessCredentialTypes.password,
                value=password,
                session=self.session,
            )
            usr_record = db_account_users.get(username, session=self.session)

        return usr_record

    def delete_user(self, username):
        return db_account_users.delete(username, session=self.session)

    def get_user(self, username):
        return db_account_users.get(username, session=self.session)

    def get_user_by_uuid(self, uuid):
        return db_account_users.get_by_uuid(uuid, session=self.session)

    def list_users(self, account_name=None):
        if account_name:

            return db_account_users.list_for_account(account_name, session=self.session)
        else:
            return db_account_users.get_all(session=self.session)

    def add_user_credential(
        self, username, credential_type, value=None, overrwite=True
    ):
        """
        Add a new password to a user

        :param username:
        :param credential_type: UserAccessCredentialType
        :param value: str value to set, may be None and if password, one will be generated
        :return:
        """
        credential = db_account_users.add_user_credential(
            username=username,
            credential_type=credential_type,
            value=value,
            session=self.session,
        )
        return credential

    def delete_user_credential(self, username, cred_type):
        return db_account_users.delete_user_credential(
            username, credential_type=cred_type, session=self.session
        )
