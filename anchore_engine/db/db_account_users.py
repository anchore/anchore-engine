"""
Interface to the account_users table. Data format is dicts, not objects.
"""

from passlib import pwd
from anchore_engine.db import AccountUser, AccessCredential, UserAccessCredentialTypes
from anchore_engine.db.entities.common import anchore_now


class UserNotFoundError(Exception):
    def __init__(self, username):
        super(UserNotFoundError, self).__init__('User not found. Username={}'.format(username))
        self.username = username


class UserAlreadyExistsError(Exception):
    def __init__(self, account_name, username):
        super(UserAlreadyExistsError, self).__init__('User already exists. account={} username={}'.format(account_name, username))
        self.account_name = account_name
        self.username = username


class CredentialAlreadyExistsError(Exception):
    def __init__(self, account_name, username, cred_type):
        super(CredentialAlreadyExistsError, self).__init__(
            'User already exists. account={} username={} cred_typ={}'.format(account_name, username, cred_type))
        self.account_name = account_name
        self.username = username
        self.credential_type = cred_type


def _generate_password():
    """
    Returns a randomly generated string of up to 32 characters
    :return: str
    """

    return pwd.genword(entropy=48)


def add(account_name, username, session):
    """
    Create a new user, raising error on conflict

    :param accountId: str
    :param username: str
    :param password: str
    :param access_type: type of access for this credential
    :param session:
    :return:
    """

    user_to_create = session.query(AccountUser).filter_by(username=username).one_or_none()

    if user_to_create is None:
        user_to_create = AccountUser()
        user_to_create.account_name = account_name
        user_to_create.username = username
        user_to_create.created_at = anchore_now()
        user_to_create.last_updated = anchore_now()
        session.add(user_to_create)
        session.flush()
    else:
        raise UserAlreadyExistsError(account_name, username)

    return user_to_create.to_dict()


def add_user_credential(username, credential_type=UserAccessCredentialTypes.password, value=None, overrwrite=True, session=None):
    usr = session.query(AccountUser).filter_by(username=username).one_or_none()

    if not usr:
        raise UserNotFoundError(username)

    matching = [obj for obj in filter(lambda x: x.type == credential_type, usr.credentials)]
    if overrwrite:
        for existing in matching:
            session.delete(existing)
    else:
        if matching:
            raise CredentialAlreadyExistsError(usr['account_name'], username, credential_type)

    credential = AccessCredential()
    credential.user = usr
    credential.username = usr.username
    credential.type = credential_type
    credential.created_at = anchore_now()

    # TODO: pass thru the encrypter

    if value:
        credential.value = value
    else:
        credential.value = _generate_password()

    session.add(credential)

    return credential.to_dict()


def delete_user_credential(username, credential_type, session):
    cred = session.query(AccessCredential).filter_by(username=username, type=credential_type).one_or_none()
    if cred:
        session.delete(cred)

    return True


def get_all(session):
    return [x.to_dict() for x in session.query(AccountUser)]


def get(username, session=None):
    usr = session.query(AccountUser).filter_by(username=username).one_or_none()
    if usr:
        return usr.to_dict()
    else:
        return None


def list_for_account(accountname, session=None):
    users = session.query(AccountUser).filter_by(account_name=accountname)
    if users:
        return [u.to_dict() for u in users]
    else:
        return []


def delete(username, session=None):
    result = session.query(AccountUser).filter_by(username=username).one_or_none()
    if result:
        session.delete(result)
        return True
    else:
        return False
