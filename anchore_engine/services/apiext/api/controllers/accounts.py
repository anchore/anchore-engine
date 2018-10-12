"""
API handlers for /accounts routes in the External API

"""
import datetime

from anchore_engine.apis import ApiRequestContextProxy
from anchore_engine.db import AccountTypes, UserAccessCredentialTypes, session_scope
from anchore_engine.db.db_accounts import AccountAlreadyExistsError, AccountNotFoundError
from anchore_engine.db.db_account_users import UserAlreadyExistsError, UserNotFoundError
from anchore_engine.utils import datetime_to_rfc2339
from anchore_engine.common.helpers import make_response_error
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.apis.authorization import get_authorizer, ParameterBoundValue, ActionBoundPermission
from anchore_engine.configuration.localconfig import ADMIN_USERNAME, ADMIN_ACCOUNT_NAME, SYSTEM_ACCOUNT_NAME, SYSTEM_USERNAME


authorizer = get_authorizer()


def account_db_to_msg(account):
    if account is None:
        return None

    return {
        'name': account['name'],
        'email': account['email'],
        'is_active': account['is_active'],
        'type': account['type'] if type(account['type']) == str else account['type'].value ,
        'created_at': datetime_to_rfc2339(datetime.datetime.utcfromtimestamp(account['created_at'])),
        'last_updated': datetime_to_rfc2339(datetime.datetime.utcfromtimestamp(account['last_updated'])),
        'created_by': account['created_by']
    }


def account_db_to_status_msg(account):
    if account is None:
        return None

    return {
        'is_active': account['is_active']
    }


def user_db_to_msg(user):
    if user is None:
        return None

    return {
        'username': user['username'],
        'created_at': datetime_to_rfc2339(datetime.datetime.utcfromtimestamp(user['created_at'])),
        'last_updated': datetime_to_rfc2339(datetime.datetime.utcfromtimestamp(user['last_updated'])),
        'created_by': user['created_by']
    }


def credential_db_to_msg(credential):
    if credential is None:
        return None

    return {
        'type': credential['type'].value,
        'value': ''.join(['*' for _ in credential['value']]),
        'created_at': datetime_to_rfc2339(datetime.datetime.utcfromtimestamp(credential['created_at'])),
        'created_by': credential['created_by']
    }


def can_delete(user):
    """
    Return if the user/account can be deleted (is allowed based on type, eg. not a service account)
    :param user:
    :return:
    """
    if user['username'] in [SYSTEM_USERNAME, ADMIN_USERNAME] or \
        user['account_name'] in [SYSTEM_ACCOUNT_NAME, ADMIN_ACCOUNT_NAME] or \
        user['account']['type'] != AccountTypes.user:
        return False
    else:
        return True


def can_deactivate(user):
    if user['username'] in [SYSTEM_USERNAME, ADMIN_USERNAME] or \
        user['account_name'] in [SYSTEM_ACCOUNT_NAME] or \
        user['account']['type'] == AccountTypes.service:
        return False
    else:
        return True


def verify_account(accountname, mgr):
    accnt = mgr.get_account(accountname)
    if not accnt:
        raise AccountNotFoundError(accountname)
    if accnt['type'] == AccountTypes.service:
        raise Exception('Bad Request')
    return accnt


def verify_user(username, accountname, mgr):
    usr = mgr.get_user(username)
    if not usr or usr['account_name'] != accountname:
        raise UserNotFoundError(username)
    if usr['account']['type'] == AccountTypes.service:
        raise Exception('Bad Request')
    return usr


@authorizer.requires([])
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
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME)])
def list_accounts(is_active=None):
    """
    GET /accounts

    :param active:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            if is_active is not None:
                response = filter(lambda x: x['is_active'] == is_active, mgr.list_accounts())
            else:
                response = mgr.list_accounts()

            return list(map(account_db_to_msg, response)), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error('Error listing accounts', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME)])
def create_account(account):
    """
    POST /accounts

    :param account:
    :return:
    """

    try:
        if account.get('type') != AccountTypes.user.value:
            return make_response_error('Invalid account type: {}. Only valid value is "user"'.format(account.get('type')), in_httpcode=400), 400

        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            resp = mgr.create_account(account_name=account['name'], account_type=account.get('type', AccountTypes.user.value), email=account.get('email'), creator=ApiRequestContextProxy.identity().username)
        return account_db_to_msg(resp), 200
    except AccountAlreadyExistsError as ex:
        return make_response_error(errmsg='Account already exists', in_httpcode=400), 400
    except Exception as ex:
        logger.exception('Unexpected Error creating account')
        return make_response_error('Error creating account', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME, target=ParameterBoundValue('accountname'))])
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
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error('Error getting account', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME, target=ParameterBoundValue('accountname'))])
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
            if account['type'] != AccountTypes.user:
                return make_response_error('Cannot delete non-user accounts', in_httpcode=400), 400
            else:
                resp = mgr.delete_account(accountname)
            return None, 204
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Error deleting account', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME, target=ParameterBoundValue('accountname'))])
def activate_account(accountname):
    """
    POST /accounts/{accountname}/activate

    idempotently activate an account

    :param accountname: str account name to activate
    :return: account json object
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            verify_account(accountname, mgr)

            result = mgr.activate_account(accountname)
            if result:
                return account_db_to_status_msg(result), 200
            else:
                return make_response_error('Error updating account state'), 500
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Error activating account', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=SYSTEM_ACCOUNT_NAME, target=ParameterBoundValue('accountname'))])
def deactivate_account(accountname):
    """
    POST /accounts/{accountname}/deactivate
    :param accountname: str account Id to deactivate
    :return: account json object
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            verify_account(accountname, mgr)

            result = mgr.deactivate_account(accountname)
            if result:
                return account_db_to_status_msg(result), 200
            else:
                return make_response_error('Error updating account state'), 500
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Internal error deactivating account', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'))])
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
                return make_response_error('No such account', in_httpcode=404), 404

            response = list(map(user_db_to_msg, users))
            return response, 200
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Error listing account users', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'), target=ParameterBoundValue('username'))])
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
        return make_response_error('User not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Error getting user record', in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'))])
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
            usr = mgr.create_user(account_name=accountname, username=user['username'], creator_name=ApiRequestContextProxy.identity().username, password=user['password'])
            return user_db_to_msg(usr), 200
    except UserAlreadyExistsError as ex:
        return make_response_error('User already exists', in_httpcode=400), 400
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Internal error deleting account {}'.format(accountname)), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'), target=ParameterBoundValue('username'))])
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

            # For now, only support passwords via the api
            if credential['type'] != 'password':
                return make_response_error('Invalid credential type', in_httpcode=404), 404

            if not credential.get('value'):
                return make_response_error('Invalid credential value, must be non-null and non-empty', in_httpcode=400), 400

            try:
                cred_type = UserAccessCredentialTypes(credential['type'])
            except:
                return make_response_error(errmsg='Invalid credential type', in_httpcode=400), 400

            cred = mgr.add_user_credential(username=username, creator_name=ApiRequestContextProxy.identity().username, credential_type=cred_type, value=credential['value'])

            return credential_db_to_msg(cred), 200
    except UserNotFoundError as ex:
        return make_response_error('User not found', in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Internal error creating credential {}'.format(accountname)), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'), target=ParameterBoundValue('username'))])
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
            cred = usr['credentials'].get(UserAccessCredentialTypes.password)
            if cred is None:
                return [], 200
            else:
                cred = credential_db_to_msg(cred)
                return [cred], 200
    except UserNotFoundError as ex:
        return make_response_error('User not found', in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as ex:
        logger.exception('Api Error')
        return make_response_error(errmsg=str(ex), in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'), target=ParameterBoundValue('username'))])
def delete_user_credential(accountname, username, credential_type):
    """
    DELETE /accounts/{accountname}/users/{username}/credentials?credential_type=password
    :param username:
    :param credential_type:
    :return:
    """

    if not credential_type:
        return make_response_error('credential type must be specified', in_httpcode=400), 400

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            usr = verify_user(username, accountname, mgr)
            if credential_type != 'password':
                return make_response_error('Invalid credential type', in_httpcode=400), 400

            if username == ApiRequestContextProxy.identity().username:
                return make_response_error('Cannot delete credential of authenticated user', in_httpcode=400), 400

            resp = mgr.delete_user_credential(username, credential_type)
            return None, 204
    except UserNotFoundError as ex:
        return make_response_error('User not found', in_httpcode=404), 404
    except AccountNotFoundError as ex:
        return make_response_error('Account not found', in_httpcode=404), 404
    except Exception as ex:
        logger.exception('Api Error')
        return make_response_error(errmsg=str(ex), in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=ParameterBoundValue('accountname'), target=ParameterBoundValue('username'))])
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
            if not can_delete(usr):
                return make_response_error('User not allowed to be deleted due to system constraints', in_httpcode=400), 400
            elif ApiRequestContextProxy.identity().username == username:
                return make_response_error('Cannot delete credential used for authentication of the request', in_httpcode=400), 400
            else:
                if mgr.delete_user(username):
                    return None, 204
                else:
                    return make_response_error('Failed to delete user: {}'.format(username), in_httpcode=500), 500
    except (UserNotFoundError, AccountNotFoundError):
        return make_response_error('User not found', in_httpcode=404), 404
    except Exception as e:
        logger.exception('API Error')
        return make_response_error('Internal error deleting user {}'.format(username), in_httpcode=500), 500
