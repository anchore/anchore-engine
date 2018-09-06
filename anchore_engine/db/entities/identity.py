from collections import namedtuple
import enum
import re

from sqlalchemy import Column, String, Boolean, Enum, Integer, ForeignKey
from sqlalchemy.orm import relationship

from anchore_engine.db.entities.common import Base, UtilMixin, anchore_now, anchore_uuid


class AccountTypes(enum.Enum):
    """
    Covers basic account types, used for authorization in the default authorizer.
    External account type is reserved for use when configured to use external identity providers but where a record is needed in this db for id consistency

    """
    user = 'user'  # Regular user
    admin = 'admin'  # User admin, only one of these per system, the principal admin account for creating other accounts
    service = 'service'  # System internal accounts for things like services
    external = 'external' # Identity managed by an external identity provider


id_sanitizer = re.compile('[a-zA-Z0-9\-_+]+')


class Account(Base, UtilMixin):
    """
    Accounts are the entities that own resources. All users within an account share a resource pool.

    """
    __tablename__ = 'accounts'

    name = Column(String, primary_key=True)
    is_active = Column(Boolean, default=True)
    type = Column(Enum(AccountTypes, name='account_types'))
    email = Column(String)
    created_by = Column(String, nullable=False)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)

    users = relationship('AccountUser', back_populates='account', lazy='dynamic', cascade=['all'])

    @staticmethod
    def sanitize_accountname(name):
        return bool(re.fullmatch(id_sanitizer, name))


class AccountUser(Base, UtilMixin):
    """
    A user can login and assume the rights of the containing account, basically, individual credentials.
    Users of external accounts are not expected, or allowed, to have credentials in this db since those are managed externally and could lead to conflict

    """
    __tablename__ = 'account_users'

    username = Column(String, primary_key=True) # Enforce globally unique user names
    account_name = Column(String, ForeignKey(Account.name), index=True)
    created_by = Column(String, nullable=False)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, default=anchore_now)

    account = relationship('Account', back_populates='users', lazy='joined', innerjoin=True)
    credentials = relationship('AccessCredential', back_populates='user', lazy='joined', cascade=['all'])

    def to_dict(self):
        """
        Override the base imple to include credentials
        :return: dictionary
        """
        value = super(AccountUser, self).to_dict()
        value['credentials'] = { cred.type : cred.to_dict() for cred in self.credentials } if self.credentials else {}
        value['account'] = self.account.to_dict()
        return value

    @staticmethod
    def sanitize_username(usr):
        return bool(re.fullmatch(id_sanitizer, usr))

    def is_external_user(self):
        return self.account.type == AccountTypes.external


class UserAccessCredentialTypes(enum.Enum):
    password = 'password'
    token = 'token' # Reserved but not currently used


class AccessCredential(Base, UtilMixin):
    """
    A login credential value for authenticating users
    """
    __tablename__ = 'user_access_credentials'

    username = Column(String, ForeignKey(AccountUser.username), primary_key=True)
    type = Column(Enum(UserAccessCredentialTypes, name='user_access_credential_types'), primary_key=True)
    value = Column(String, nullable=False)
    created_by = Column(String, nullable=False, index=True)
    created_at = Column(Integer, default=anchore_now)

    user = relationship('AccountUser', back_populates='credentials', lazy='joined')