"""
API handlers for /accounts routes in the External API

"""
import datetime

from anchore_engine.apis import ApiRequestContextProxy
from anchore_engine.apis.authorization import (
    ActionBoundPermission,
    NotificationTypes,
    ParameterBoundValue,
    RequestingAccountValue,
    get_authorizer,
)
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.configuration.localconfig import (
    DELETE_PROTECTED_ACCOUNT_TYPES,
    DELETE_PROTECTED_USER_NAMES,
    GLOBAL_RESOURCE_DOMAIN,
    RESERVED_ACCOUNT_NAMES,
    USER_MOD_PROTECTED_ACCOUNT_NAMES,
    get_config,
    load_policy_bundles,
)
from anchore_engine.db import (
    AccountStates,
    AccountTypes,
    UserAccessCredentialTypes,
    UserTypes,
    session_scope,
)
from anchore_engine.db.db_account_users import UserAlreadyExistsError, UserNotFoundError
from anchore_engine.db.db_accounts import (
    AccountAlreadyExistsError,
    AccountNotFoundError,
    DisableAdminAccountError,
    InvalidStateError,
)
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.utils import datetime_to_rfc3339

authorizer = get_authorizer()


def account_db_to_msg(account):
    if account is None:
        return None

    return {
        "name": account["name"],
        "email": account["email"],
        "state": account["state"].value
        if type(account["state"]) != str
        else account["state"],
        "type": account["type"]
        if type(account["type"]) == str
        else account["type"].value,
        "created_at": datetime_to_rfc3339(
            datetime.datetime.utcfromtimestamp(account["created_at"])
        ),
        "last_updated": datetime_to_rfc3339(
            datetime.datetime.utcfromtimestamp(account["last_updated"])
        ),
    }


def account_db_to_status_msg(account):
    if account is None:
        return None

    return {
        "state": account["state"].value
        if type(account["state"]) != str
        else account["state"],
    }


def user_db_to_msg(user):
    if user is None:
        return None

    return {
        "username": user["username"],
        "type": user["type"].value,
        "source": user["source"],
        "created_at": datetime_to_rfc3339(
            datetime.datetime.utcfromtimestamp(user["created_at"])
        ),
        "last_updated": datetime_to_rfc3339(
            datetime.datetime.utcfromtimestamp(user["last_updated"])
        ),
    }


def credential_db_to_msg(credential):
    if credential is None:
        return None

    return {
        "type": credential["type"].value,
        "value": "".join(["*" for _ in credential["value"]]),
        "created_at": datetime_to_rfc3339(
            datetime.datetime.utcfromtimestamp(credential["created_at"])
        ),
    }


def can_create_account(account_dict):
    if not account_dict.get("name"):
        raise ValueError('"name" is required')

    if account_dict.get("name") in RESERVED_ACCOUNT_NAMES:
        raise ValueError("Cannot use name {}".format(account_dict.get("name")))

    if account_dict.get("type") and account_dict.get("type") != "user":
        raise ValueError(
            'Account type must be "user", found: {}'.format(account_dict.get("type"))
        )

    return True


def can_delete_user(user):
    """
    Return if the user can be deleted (is allowed based on type, eg. not a service account)
    :param user:
    :return:
    """
    if (
        user["username"] in DELETE_PROTECTED_USER_NAMES
        or user["account_name"] in USER_MOD_PROTECTED_ACCOUNT_NAMES
        or user["account"]["type"] in [AccountTypes.service]
    ):
        return False
    else:
        return True


def can_delete_account(account):
    """
    Return if the user can be deleted (is allowed based on type, eg. not a service account)
    :param user:
    :return:
    """
    if (
        account["name"] in USER_MOD_PROTECTED_ACCOUNT_NAMES
        or account["type"] in DELETE_PROTECTED_ACCOUNT_TYPES
    ):
        return False
    else:
        return True


def verify_account(accountname, mgr):
    accnt = mgr.get_account(accountname)
    if not accnt:
        raise AccountNotFoundError(accountname)
    if accnt["type"] == AccountTypes.service:
        raise Exception("Bad Request")
    return accnt


def verify_user(username, accountname, mgr):
    usr = mgr.get_user(username)
    if not usr or usr["account_name"] != accountname:
        raise UserNotFoundError(username)
    if usr["account"]["type"] == AccountTypes.service:
        raise Exception("Bad Request")
    return usr


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_users_account():
    """
    GET /account

    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            account = mgr.get_account(ApiRequestContextProxy.namespace())
            return account_db_to_msg(account), 200
    except Exception as ex:
        logger.exception("API Error")
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def list_accounts(state=None):
    """
    GET /accounts

    :param active:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            if state is not None:
                try:
                    state = AccountStates(state)
                except:
                    return (
                        make_response_error(
                            "Bad Request: state {} not a valid value", in_httpcode=400
                        ),
                        400,
                    )

            response = mgr.list_accounts(with_state=state)

            return list(map(account_db_to_msg, response)), 200
    except Exception as ex:
        logger.exception("API Error")
        return make_response_error("Error listing accounts", in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def create_account(account):
    """
    POST /accounts

    :param account:
    :return:
    """

    try:
        try:
            can_create_account(account)
        except ValueError as ex:
            return (
                make_response_error(
                    "Invalid account request: {}".format(ex.args[0]), in_httpcode=400
                ),
                400,
            )
        except Exception as ex:
            logger.exception("Unexpected exception in account validation")
            return make_response_error("Invalid account request", in_httpcode=400), 400

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            try:
                resp = mgr.create_account(
                    account_name=account["name"],
                    account_type=account.get("type", AccountTypes.user.value),
                    email=account.get("email"),
                )
            except ValueError as ex:
                return (
                    make_response_error(
                        "Validation failed: {}".format(ex), in_httpcode=400
                    ),
                    400,
                )

            authorizer.notify(NotificationTypes.domain_created, account["name"])

            # Initialize account stuff
            try:
                _init_policy(account["name"], config=get_config())
            except Exception:
                logger.exception(
                    "Could not initialize policy bundle for new account: {}".format(
                        account["name"]
                    )
                )
                raise

        return account_db_to_msg(resp), 200
    except AccountAlreadyExistsError as ex:
        return (
            make_response_error(errmsg="Account already exists", in_httpcode=400),
            400,
        )
    except Exception as ex:
        logger.exception("Unexpected Error creating account")
        return make_response_error("Error creating account", in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue("accountname"))])
def get_account(accountname):
    """
    GET /accounts/{accountname}

    :param accountname:
    :return:
    """

    try:

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            account = verify_account(accountname, mgr)
            return account_db_to_msg(account), 200
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as ex:
        logger.exception("API Error")
        return make_response_error("Error getting account", in_httpcode=500), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=GLOBAL_RESOURCE_DOMAIN, target=ParameterBoundValue("accountname")
        )
    ]
)
def delete_account(accountname):
    """
    DELETE /account/{accountname}

    :param accountname:
    :return:
    """

    try:

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            account = verify_account(accountname, mgr)
            if not can_delete_account(account):
                return (
                    make_response_error("Account cannot be deleted", in_httpcode=400),
                    400,
                )
            else:
                account = mgr.update_account_state(accountname, AccountStates.deleting)

                # Flush from authz system if necessary
                authorizer.notify(NotificationTypes.domain_deleted, accountname)

                users = mgr.list_users(accountname)
                for user in users:
                    # Flush users
                    logger.debug(
                        "Deleting account user {} on authz system if using plugin".format(
                            user["username"]
                        )
                    )
                    authorizer.notify(
                        NotificationTypes.principal_deleted, user["username"]
                    )

                    logger.debug("Deleting account user: {}".format(user["username"]))
                    mgr.delete_user(user["username"])

            return account_db_to_status_msg(account), 200
    except InvalidStateError as ex:
        return make_response_error(str(ex), in_httpcode=400), 400
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return make_response_error("Error deleting account", in_httpcode=500), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=GLOBAL_RESOURCE_DOMAIN, target=ParameterBoundValue("accountname")
        )
    ]
)
def update_account_state(accountname, desired_state):
    """
    POST /accounts/{accountname}/state

    Body: {"state": "enabled"|"disabled"}

    :param accountname: str account name to update
    :param desired_state: json object for desired state to set
    :return: account json object
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            verify_account(accountname, mgr)
            result = mgr.update_account_state(
                accountname, AccountStates(desired_state.get("state"))
            )
            if result:
                return account_db_to_status_msg(result), 200
            else:
                return make_response_error("Error updating account state"), 500
    except (InvalidStateError, DisableAdminAccountError) as ex:
        return make_response_error(str(ex), in_httpcode=400), 400
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return make_response_error("Error updating account state", in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue("accountname"))])
def list_users(accountname):
    """
    GET /accounts/{accountname}/users

    :param account:
    :return:
    """

    try:

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            verify_account(accountname, mgr)

            users = mgr.list_users(accountname)
            if users is None:
                return make_response_error("No such account", in_httpcode=404), 404

            response = list(map(user_db_to_msg, users))
            return response, 200
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return make_response_error("Error listing account users", in_httpcode=500), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=ParameterBoundValue("accountname"),
            target=ParameterBoundValue("username"),
        )
    ]
)
def get_account_user(accountname, username):
    """
    GET /accounts/{accountname}/users/{username}

    :param accountname:
    :param username:
    :return:
    """

    try:

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            user = verify_user(username, accountname, mgr)

            response = user_db_to_msg(user)
            return response, 200
    except (UserNotFoundError, AccountNotFoundError):
        return make_response_error("User not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return make_response_error("Error getting user record", in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue("accountname"))])
def create_user(accountname, user):
    """
    POST /accounts/{accountname}/users

    :param accountname:
    :param user:
    :return:
    """

    try:

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            verify_account(accountname, mgr)

            try:
                usr = mgr.create_user(
                    account_name=accountname,
                    username=user["username"],
                    password=user["password"],
                )
            except ValueError as ex:
                return (
                    make_response_error(
                        "Validation failed: {}".format(ex), in_httpcode=400
                    ),
                    400,
                )

            # Flush from authz system if necessary, will rollback if this fails, but rely on the db state checks first to gate this
            authorizer.notify(NotificationTypes.principal_created, usr["username"])

            return user_db_to_msg(usr), 200
    except UserAlreadyExistsError as ex:
        return make_response_error("User already exists", in_httpcode=400), 400
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return make_response_error("Internal error adding user"), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=ParameterBoundValue("accountname"),
            target=ParameterBoundValue("username"),
        )
    ]
)
def create_user_credential(accountname, username, credential):
    """
    POST /accounts/{accountname}/users/{username}/credentials
    :param accountname: str account id for account account record
    :param username: str username
    :param credential: json object of the credential type
    :return: credential json object
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            user = verify_user(username, accountname, mgr)

            if user["type"] != UserTypes.native:
                return (
                    make_response_error(
                        "Users with type other than 'native' cannot have password credentials",
                        in_httpcode=400,
                    ),
                    400,
                )

            # For now, only support passwords via the api
            if credential["type"] != "password":
                return (
                    make_response_error("Invalid credential type", in_httpcode=404),
                    404,
                )

            if not credential.get("value"):
                return (
                    make_response_error(
                        "Invalid credential value, must be non-null and non-empty",
                        in_httpcode=400,
                    ),
                    400,
                )

            try:
                cred_type = UserAccessCredentialTypes(credential["type"])
            except:
                return (
                    make_response_error(
                        errmsg="Invalid credential type", in_httpcode=400
                    ),
                    400,
                )

            cred = mgr.add_user_credential(
                username=username, credential_type=cred_type, value=credential["value"]
            )

            return credential_db_to_msg(cred), 200
    except UserNotFoundError as ex:
        return make_response_error("User not found", in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return (
            make_response_error(
                "Internal error creating credential {}".format(accountname)
            ),
            500,
        )


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=ParameterBoundValue("accountname"),
            target=ParameterBoundValue("username"),
        )
    ]
)
def list_user_credentials(accountname, username):
    """
    GET /accounts/{accountname}/users/{username}/credentials

    :param username:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            usr = verify_user(username, accountname, mgr)
            cred = usr["credentials"].get(UserAccessCredentialTypes.password)
            if cred is None:
                return [], 200
            else:
                cred = credential_db_to_msg(cred)
                return [cred], 200
    except UserNotFoundError as ex:
        return make_response_error("User not found", in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as ex:
        logger.exception("Api Error")
        return make_response_error(errmsg=str(ex), in_httpcode=500), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=ParameterBoundValue("accountname"),
            target=ParameterBoundValue("username"),
        )
    ]
)
def delete_user_credential(accountname, username, credential_type):
    """
    DELETE /accounts/{accountname}/users/{username}/credentials?credential_type=password
    :param username:
    :param credential_type:
    :return:
    """

    if not credential_type:
        return (
            make_response_error("credential type must be specified", in_httpcode=400),
            400,
        )

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            usr = verify_user(username, accountname, mgr)
            if credential_type != "password":
                return (
                    make_response_error("Invalid credential type", in_httpcode=400),
                    400,
                )

            if username == ApiRequestContextProxy.identity().username:
                return (
                    make_response_error(
                        "Cannot delete credential of authenticated user",
                        in_httpcode=400,
                    ),
                    400,
                )

            resp = mgr.delete_user_credential(username, credential_type)
            return None, 204
    except UserNotFoundError as ex:
        return make_response_error("User not found", in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error("Account not found", in_httpcode=404), 404
    except Exception as ex:
        logger.exception("Api Error")
        return make_response_error(errmsg=str(ex), in_httpcode=500), 500


@authorizer.requires(
    [
        ActionBoundPermission(
            domain=ParameterBoundValue("accountname"),
            target=ParameterBoundValue("username"),
        )
    ]
)
def delete_user(accountname, username):
    """
    DELETE /accounts/{accountname}/users/{username}

    :param accountname:
    :param username: the user to delete
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            usr = verify_user(username, accountname, mgr)
            if not can_delete_user(usr):
                return (
                    make_response_error(
                        "User not allowed to be deleted due to system constraints",
                        in_httpcode=400,
                    ),
                    400,
                )
            elif ApiRequestContextProxy.identity().username == username:
                return (
                    make_response_error(
                        "Cannot delete credential used for authentication of the request",
                        in_httpcode=400,
                    ),
                    400,
                )
            else:
                if mgr.delete_user(username):
                    # Flush from authz system if necessary, will rollback if this fails, but rely on the db state checks first to gate this
                    authorizer.notify(NotificationTypes.principal_deleted, username)

                    return None, 204
                else:
                    return (
                        make_response_error(
                            "Failed to delete user: {}".format(username),
                            in_httpcode=500,
                        ),
                        500,
                    )
    except (UserNotFoundError, AccountNotFoundError):
        return make_response_error("User not found", in_httpcode=404), 404
    except Exception as e:
        logger.exception("API Error")
        return (
            make_response_error(
                "Internal error deleting user {}".format(username), in_httpcode=500
            ),
            500,
        )


# TODO: move this to the catalog when all account/user modifications are handled there
def _init_policy(accountname, config):
    """
    Initialize a new bundle for the given accountname

    :return: bool indicating if bundle was created or not (False means one already existed)
    """

    client = internal_client_for(CatalogClient, accountname)
    policies = client.list_policies()

    if len(policies) == 0:
        logger.debug(
            "Account {} has no policy bundle - installing default".format(accountname)
        )

        # What to do with each policy bundle
        def process_bundle(policy_bundle, bundle):
            resp = client.add_policy(bundle, active=policy_bundle["active"])
            if not resp:
                raise Exception(
                    "policy bundle {} DB add failed".format(str(policy_bundle))
                )

        # How to handle any exceptions form opening the bundle file or converting its contents
        # to json
        def process_exception(exception):
            logger.error(
                "could not load up bundles for user - exception: " + str(exception)
            )
            raise

        try:
            load_policy_bundles(config, process_bundle, process_exception)
        except Exception:
            raise
    else:
        logger.debug(
            "Existing bundle found for account: {}. Not expected on invocations of this function in most uses".format(
                accountname
            )
        )
        return False
