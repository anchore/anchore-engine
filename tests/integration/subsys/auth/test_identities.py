import pytest

from anchore_engine.configuration import localconfig
from anchore_engine.db import AccountTypes, session_scope
from anchore_engine.subsys import identities, logger


def tearDown():
    with session_scope() as session:
        mgr = identities.manager_factory.for_session(session)
        for accnt in mgr.list_accounts():
            logger.info("Deleting accnt: {}".format(accnt))
            mgr.delete_account(accnt["name"])


def test_initialize_identities(anchore_db, monkeypatch):
    monkeypatch.setattr(
        localconfig, "localconfig", {"default_admin_password": "foobar"}
    )

    try:
        with session_scope() as session:
            bootstrapper = identities.IdentityBootstrapper(
                identities.IdentityManager, session
            )
            bootstrapper.initialize_system_identities()

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            accnt1 = mgr.get_account(localconfig.SYSTEM_ACCOUNT_NAME)
            logger.info(str(accnt1))
            assert AccountTypes.service == accnt1["type"]

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            user1, creds1 = mgr.get_credentials_for_username(
                localconfig.SYSTEM_ACCOUNT_NAME
            )

        logger.info(creds1)
        assert user1 is not None
        assert creds1 is not None
    finally:
        tearDown()


def test_unset_default_password(anchore_db, monkeypatch):
    with pytest.raises(Exception) as excinfo:
        with session_scope() as session:
            bootstrapper = identities.IdentityBootstrapper(
                identities.IdentityManager, session
            )
            bootstrapper.initialize_system_identities()

    assert "No default admin password provided" in str(excinfo.value)


def test_initialize_users(anchore_db):
    try:
        test_creds = {
            "users": {
                "user1": {"password": "abc123", "email": "user1@email"},
                "user2": {"password": "def466", "email": "user2@email"},
            }
        }

        with session_scope() as session:
            bootstrapper = identities.IdentityBootstrapper(
                identities.IdentityManager, session
            )
            bootstrapper.initialize_user_identities_from_config(test_creds)

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            accnt1 = mgr.get_account("user1")

        logger.info(str(accnt1))
        assert accnt1 is not None

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            user1, cred1 = mgr.get_credentials_for_username("user1")

        logger.info(str(cred1))
        assert cred1 is not None

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            accnt2 = mgr.get_account("user2")

        logger.info(str(accnt2))
        assert accnt2 is not None

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            user2, cred2 = mgr.get_credentials_for_username("user2")

        logger.info(str(cred2))
        assert cred2 is not None
    finally:
        tearDown()


def test_create(anchore_db):
    try:
        logger.info("Creating user account/users")
        fixtures = [
            ("user_Account1", "user1", AccountTypes.user),
            ("admin_Account1", "user2", AccountTypes.admin),
            ("system_account1", "user3", AccountTypes.user),
        ]

        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)

            for account_name, user_name, account_type in fixtures:
                mgr.create_account(
                    account_name=account_name, account_type=account_type, email="blah"
                )
                accnt = mgr.get_account(account_name)
                assert accnt is not None
                assert account_type == accnt["type"]

                mgr.create_user(
                    username=user_name,
                    account_name=account_name,
                    password="password123",
                )
                usr = mgr.get_user(user_name)
                assert usr is not None
                assert account_name == usr["account_name"]
    finally:
        tearDown()
