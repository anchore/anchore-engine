"""
Common fixtures for use in any test, not specific to a thing being tested.

"""

import os

import pytest

from anchore_engine.subsys import logger

logger.enable_test_logging()


@pytest.fixture()
def anchore_db(connection_str=None, do_echo=False):
    """
    Sets up a db connection to an existing db, and fails if not found/present
    :return:
    """

    from anchore_engine.db.entities.common import (
        do_disconnect,
        end_session,
        get_engine,
        init_thread_session,
        initialize,
    )
    from anchore_engine.db.entities.upgrade import do_create_tables

    conn_str = connection_str if connection_str else os.getenv("ANCHORE_TEST_DB_URL")

    config = {"credentials": {"database": {"db_connect": conn_str, "db_echo": do_echo}}}

    try:
        logger.info("Initializing connection: {}".format(config))
        ret = initialize(localconfig=config)
        init_thread_session(force_new=True)

        engine = get_engine()
        logger.info("Dropping db if found")
        engine.execute("DROP SCHEMA public CASCADE")
        engine.execute("CREATE SCHEMA public")
        engine.execute("GRANT ALL ON SCHEMA public TO postgres")
        engine.execute("GRANT ALL ON SCHEMA public TO public")

        # Now ready for anchore init (tables etc)
        logger.info("Creating tables")
        do_create_tables()

        yield ret
    finally:
        logger.info("Cleaning up/disconnect")
        end_session()
        do_disconnect()


@pytest.fixture(scope="class")
def cls_anchore_db(connection_str=None, do_echo=False):
    """
    Sets up a db connection to an existing db, and fails if not found/present.

    This is for use in legacy unittest frameworks where it is set once at the class level, not on each function.
    :return:
    """

    from anchore_engine.db.entities.common import (
        do_disconnect,
        end_session,
        get_engine,
        init_thread_session,
        initialize,
    )
    from anchore_engine.db.entities.upgrade import do_create_tables

    conn_str = connection_str if connection_str else os.getenv("ANCHORE_TEST_DB_URL")

    config = {"credentials": {"database": {"db_connect": conn_str, "db_echo": do_echo}}}

    try:
        logger.info("Initializing connection: {}".format(config))
        ret = initialize(localconfig=config)
        init_thread_session(force_new=True)

        engine = get_engine()
        logger.info("Dropping db if found")
        engine.execute("DROP SCHEMA public CASCADE")
        engine.execute("CREATE SCHEMA public")
        engine.execute("GRANT ALL ON SCHEMA public TO postgres")
        engine.execute("GRANT ALL ON SCHEMA public TO public")

        # Now ready for anchore init (tables etc)
        logger.info("Creating tables")
        do_create_tables()

        yield ret
    finally:
        logger.info("Cleaning up/disconnect")
        end_session()
        do_disconnect()


@pytest.fixture()
def echo_anchore_db():
    def invoke():
        return anchore_db(connection_str=None, do_echo=True)

    return invoke


@pytest.fixture
def mem_db(do_echo=False):
    from anchore_engine.db.entities.common import (
        do_disconnect,
        end_session,
        get_engine,
        init_thread_session,
        initialize,
    )
    from anchore_engine.db.entities.upgrade import do_create_tables

    conn_str = "sqllite://:memory:"

    config = {"credentials": {"database": {"db_connect": conn_str, "db_echo": do_echo}}}

    try:
        logger.info("Initializing connection: {}".format(config))
        ret = initialize(localconfig=config)
        init_thread_session(force_new=True)

        engine = get_engine()
        logger.info("Dropping db if found")
        engine.execute("DROP SCHEMA public CASCADE")
        engine.execute("CREATE SCHEMA public")
        engine.execute("GRANT ALL ON SCHEMA public TO postgres")
        engine.execute("GRANT ALL ON SCHEMA public TO public")

        # Now ready for anchore init (tables etc)
        logger.info("Creating tables")
        do_create_tables()

        yield ret
    finally:
        logger.info("Cleaning up/disconnect")
        end_session()
        do_disconnect()
