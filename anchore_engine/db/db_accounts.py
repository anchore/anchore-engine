"""
Interface to the accounts table. Data format is dicts, not objects.
"""

from anchore_engine.db import Account, AccountTypes
from anchore_engine.db.entities.common import anchore_now


class AccountNotFoundError(Exception):
    def __init__(self, account_name):
        super(AccountNotFoundError, self).__init__('User account not found. Name={}'.format(account_name))
        self.account_name = account_name


class AccountAlreadyExistsError(Exception):
    def __init__(self,  account_name):
        super(AccountAlreadyExistsError, self).__init__('User account already exists. name={}'.format(account_name))
        self.account_name = account_name


def add(account_name, creator_username, is_active=True, account_type=AccountTypes.user, email=None, session=None):
    found_account = session.query(Account).filter_by(name=account_name).one_or_none()
    if found_account:
        raise AccountAlreadyExistsError(account_name)

    accnt = Account()
    accnt.name = account_name
    accnt.is_active = is_active
    accnt.type = account_type
    accnt.email = email
    accnt.created_by = creator_username
    accnt.created_at = anchore_now()
    accnt.last_updated = anchore_now()
    session.add(accnt)
    return accnt.to_dict()


def update_active_state(name, is_active, session=None):
    accnt = session.query(Account).filter_by(name=name).one_or_none()
    if not accnt:
        raise AccountNotFoundError(name)

    accnt.is_active = is_active
    return accnt.to_dict()


def get_all(is_active=None, session=None):
    if is_active is not None:
        return [x.to_dict() for x in session.query(Account).filter(Account.is_active == is_active)]
    else:
        return [x.to_dict() for x in session.query(Account)]


def get(name, session=None):
    accnt = session.query(Account).filter_by(name=name).one_or_none()
    if accnt:
        return accnt.to_dict()
    else:
        return None


def delete(name, session=None):
    accnt = session.query(Account).filter_by(name=name).one_or_none()
    if accnt:
        session.delete(accnt)
        return True
    else:
        return False
