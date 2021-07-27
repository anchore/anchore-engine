import enum
import time

from authlib.integrations.sqla_oauth2.client_mixin import OAuth2ClientMixin
from authlib.integrations.sqla_oauth2.tokens_mixins import TokenMixin
from sqlalchemy import Boolean, Column, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from anchore_engine.db.entities.common import Base, UtilMixin, anchore_now, anchore_uuid


class AccountTypes(enum.Enum):
    """
    Covers basic account types, used for authorization in the default authorizer.
    External account type is reserved for use when configured to use external identity providers but where a record is needed in this db for id consistency

    """

    user = "user"  # Regular user
    admin = "admin"  # User admin, only one of these per system, the principal admin account for creating other accounts
    service = "service"  # System internal accounts for things like services
    external = "external"  # Identity managed by an external identity provider


class UserTypes(enum.Enum):
    """
    Types of user to distinguish expected authentication requirements
    """

    native = "native"  # Users authenticated by the internal db (e.g. with passwords)
    external = "external"  # Users that exist in Anchore but are authenticated externally (e.g. SAML or LDAP)
    internal = "internal"  # Internal service users that may only authenticate via generated tokens by services themselves (e.g. jwt)


class AccountStates(enum.Enum):
    enabled = "enabled"  # Normal state, all functionality enabled
    disabled = (
        "disabled"  # No user within the account can authenticate, effectively locked
    )
    deleting = "deleting"  # Pending deletion. Holds the name in the namespace until all resources are flushed and then record is removed


class Account(Base, UtilMixin):
    """
    Accounts are the entities that own resources. All users within an account share a resource pool.

    """

    __tablename__ = "accounts"

    name = Column(String, primary_key=True)
    state = Column(
        Enum(AccountStates, name="account_states"), default=AccountStates.enabled
    )
    type = Column(
        Enum(AccountTypes, name="account_types"),
        nullable=False,
        default=AccountTypes.user,
    )
    email = Column(String)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, onupdate=anchore_now, default=anchore_now)

    users = relationship(
        "AccountUser",
        back_populates="account",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )


class AccountUser(Base, UtilMixin):
    """
    A user can login and assume the rights of the containing account, basically, individual credentials.
    Users of external accounts are not expected, or allowed, to have credentials in this db since those are managed externally and could lead to conflict

    """

    __tablename__ = "account_users"

    username = Column(String, primary_key=True)  # Enforce globally unique user names
    account_name = Column(String, ForeignKey(Account.name), index=True)
    type = Column(
        Enum(UserTypes, name="user_types"), nullable=False, default=UserTypes.native
    )
    source = Column(String)
    created_at = Column(Integer, default=anchore_now)
    last_updated = Column(Integer, default=anchore_now)
    uuid = Column(
        "uuid", String, unique=True, nullable=False, default=anchore_uuid, index=True
    )

    account = relationship(
        "Account", back_populates="users", lazy="joined", innerjoin=True
    )
    credentials = relationship(
        "AccessCredential",
        back_populates="user",
        lazy="joined",
        cascade="all, delete-orphan",
    )

    def to_dict(self):
        """
        Override the base imple to include credentials
        :return: dictionary
        """
        value = super(AccountUser, self).to_dict()
        value["credentials"] = (
            {cred.type: cred.to_dict() for cred in self.credentials}
            if self.credentials
            else {}
        )
        value["account"] = self.account.to_dict()
        return value

    def is_external_user(self):
        return self.account.type == AccountTypes.external


class UserAccessCredentialTypes(enum.Enum):
    password = "password"
    token = "token"  # Reserved but not currently used


class AccessCredential(Base, UtilMixin):
    """
    A login credential value for authenticating users
    """

    __tablename__ = "user_access_credentials"

    username = Column(String, ForeignKey(AccountUser.username), primary_key=True)
    type = Column(
        Enum(UserAccessCredentialTypes, name="user_access_credential_types"),
        primary_key=True,
    )
    value = Column(String, nullable=False)
    created_at = Column(Integer, default=anchore_now)

    user = relationship("AccountUser", back_populates="credentials", lazy="joined")


# Entities needed by authlib for oauth2 support
class OAuth2Client(Base, UtilMixin, OAuth2ClientMixin):
    __tablename__ = "oauth2_clients"

    id = Column(Integer, primary_key=True)
    user_id = Column(String)


# TODO: probably move some of this to the AccessCredential type, use the 'value' field to encode the token
class OAuth2Token(Base, UtilMixin, TokenMixin):
    __tablename__ = "oauth2_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(String)
    client_id = Column(String)
    token_type = Column(String)
    access_token = Column(String, unique=True, nullable=False)
    refresh_token = Column(String, index=True)
    scope = Column(Text, default="")
    revoked = Column(Boolean, default=False)
    issued_at = Column(Integer, nullable=False, default=lambda: int(time.time()))
    expires_in = Column(Integer, nullable=False, default=0)

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in

    def is_refresh_token_expired(self):
        return self.revoked
