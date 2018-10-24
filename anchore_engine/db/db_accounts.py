"""
Interface to the accounts table. Data format is dicts, not objects.
"""
from anchore_engine.db import Account, AccountTypes, AccountStates
from anchore_engine.db.entities.common import anchore_now


class AccountNotFoundError(Exception):
    def __init__(self, account_name):
        super(AccountNotFoundError, self).__init__('User account not found. Name={}'.format(account_name))
        self.account_name = account_name


class AccountAlreadyExistsError(Exception):
    def __init__(self,  account_name):
        super(AccountAlreadyExistsError, self).__init__('User account already exists. name={}'.format(account_name))
        self.account_name = account_name


class InvalidStateError(Exception):
    def __init__(self, current_state, desired_state):
        super(InvalidStateError, self).__init__('Invalid account state change requested. Cannot go from state {} to state {}'.format(current_state.value, desired_state.value))
        self.current_state = current_state
        self.desired_state = desired_state


def add(account_name, state=AccountStates.enabled, account_type=AccountTypes.user, email=None, session=None):
    found_account = session.query(Account).filter_by(name=account_name).one_or_none()

    if found_account:
        raise AccountAlreadyExistsError(account_name)

    accnt = Account()
    accnt.name = account_name
    accnt.state = state
    accnt.type = account_type
    accnt.email = email
    accnt.created_at = anchore_now()
    accnt.last_updated = anchore_now()
    session.add(accnt)
    return accnt.to_dict()


def update_state(name, new_state, session=None):
    """
    Update state of the account. Allowed transitions:

    active -> disabled
    disabled -> active
    disabled -> deleting

    Deleting is a terminal state, and can be reached only from disabled

    :param name:
    :param new_state:
    :param session:
    :return:
    """

    accnt = session.query(Account).filter_by(name=name).one_or_none()
    if not accnt:
        raise AccountNotFoundError(name)

    # Deleting state is terminal. Must deactivate account prior to deleting it.
    if accnt.state == AccountStates.deleting or (accnt.state == AccountStates.enabled and new_state == AccountStates.deleting):
        raise InvalidStateError(accnt.state, new_state)

    accnt.state = new_state
    return accnt.to_dict()


def get_all(with_state=None, session=None):
    if with_state is not None:
        return [x.to_dict() for x in session.query(Account).filter(Account.state == with_state)]
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
