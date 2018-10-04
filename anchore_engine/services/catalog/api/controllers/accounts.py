"""
API handlers for /accounts routes in the Catalog

"""
import datetime
from connexion import request

from anchore_engine.apis import ApiRequestContextProxy
from anchore_engine.db import AccountTypes, UserAccessCredentialTypes, session_scope
from anchore_engine.utils import datetime_to_rfc2339
from anchore_engine.common.helpers import make_response_error
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.apis.authorization import get_authorizer, Permission

authorizer = get_authorizer()


def account_db_to_msg(account):
    if account is None:
        return None

    return {
        'name': account['name'],
        'email': account['email'],
        'is_active': account['is_active'],
        'type': account['type'].value,
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
                response = filter(lambda x: x['is_active'] == is_active, mgr.list_accounts(session))
            else:
                response = mgr.list_accounts(session)

            logger.info('Accounts: {}'.format(response))

            return list(map(account_db_to_msg, response)), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def create_account(account):
    """
    POST /accounts

    :param account:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            resp = mgr.create_account(session,
                                             account_name=account['name'],
                                             account_type=account.get('type', AccountTypes.user.value),
                                             email=account.get('email'),
                                             creator=request.authorization.username
                                             )

            return account_db_to_msg(resp), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def get_account(accountname):
    """
    GET /accounts/{accountname}

    :param accountname:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            account = mgr.get_account(accountname)
            return account_db_to_msg(account), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def delete_account(accountname):
    """
    DELETE /account/{accountname}

    :param accountname:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)

            try:
                resp = mgr.delete_account(accountname)
                return '', 200
            except Exception as e:
                return make_response_error('Internal error deleting account {}'.format(accountname), ), 500
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            result = mgr.activate_account(session, accountname)

            if result:
                return account_db_to_status_msg(result), 200
            else:
                return make_response_error('Error updating account state', ), 500
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def deactivate_account(accountname):
    """
    POST /accounts/{accountname}/deactivate
    :param accountname: str account Id to deactivate
    :return: account json object
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            result = mgr.deactivate_account(accountname)
            if result:
                return account_db_to_status_msg(result), 200
            else:
                return make_response_error('Error updating account state', ), 500
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def list_users(accountname):
    """
    GET /accounts/{accountname}/users

    :param account:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            users = mgr.list_users(accountname)
            if users is None:
                return make_response_error('No such account'), 404

            response = list(map(user_db_to_msg, users))
            return response, 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def get_account_user(accountname, username):
    """
    GET /accounts/{accountname}/user/{username}

    :param accountname:
    :param username:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            user = mgr.get_user(username)

            if user is None or user.account_name != accountname:
                return make_response_error('Not found', 404)

            response = user_db_to_msg(user)
            return response, 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            usr = mgr.create_user(account_name=accountname, username=user['username'], creator_name=ApiRequestContextProxy.user(), password=user['password'])
            return user_db_to_msg(usr), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            usr = mgr.get_user(username)
            if not usr or usr['account_name'] != accountname:
                return make_response_error('Username not found in account'), 404

            # For now, only support passwords via the api
            if credential['type'] != 'password':
                return make_response_error('Invalid credential type'), 400

            if not credential.get('value'):
                return make_response_error('Invalid credential value, must be non-null and non-empty'), 400

            try:
                cred_type = UserAccessCredentialTypes(credential['type'])
            except:
                return make_response_error(errmsg='Invalid credential type'), 400

            cred = mgr.add_user_credential(session, creator_name=ApiRequestContextProxy.user(), username=username, credential_type=cred_type, value=credential['value'])

            return credential_db_to_msg(cred), 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def list_user_credentials(accountname, username):
    """
    GET /accounts/{accountname}/users/{username}/credentials

    :param username:
    :return:
    """

    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)

            usr = mgr.get_user(session, username)
            if usr['account_name'] != accountname:
                return make_response_error('Username not found in account'), 404

            cred = [credential_db_to_msg(usr.get('credentials')[0])]
            if cred is None:
                return [], 200
            else:
                return cred, 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def delete_user_credential(accountname, username, credential_type, uuid):
    """
    DELETE /accounts/{accountname}/users/{username}/credentials?uuid
    :param username:
    :param credential_type:
    :return:
    """
    try:
        with session_scope() as session:
            mgr = manager_factory.for_session(session)
            resp = mgr.delete_user_credential(username, credential_type)
            return resp, 200
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            if request.authorization.accountname == accountname:
                return make_response_error('Cannot delete credential used for authentication of the request'), 400

            user = mgr.get_user(username)
            if user['account_name'] != accountname:
                return make_response_error('username {} not valid for account {}'.format(username, accountname)), 404

            if mgr.delete_user(username):
                return '', 200
            else:
                return make_response_error('Failed to delete credential: {}'.format(accountname)), 500
    except Exception as ex:
        logger.exception('API Error')
        return make_response_error(errmsg=str(ex)), 500
