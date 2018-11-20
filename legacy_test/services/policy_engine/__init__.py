import unittest
import os
from .utils import LocalTestDataEnvironment, init_db
from legacy_test import init_test_logging
from anchore_engine.services.policy_engine.engine import logs
from anchore_engine.db.entities.common import ThreadLocalSession, Session, engine, end_session

class BaseDBUnitTest(unittest.TestCase):
    """
    Base db-backed unit test with init for the local test environment and sqlite in-memory db as well as
    simple python logging.
    """

    @classmethod
    def setup_logging(cls):
        init_test_logging()
        cls.log = logs.get_logger()

    @classmethod
    def setup_db(cls):
        init_db()

    @classmethod
    def setUpClass(cls):
        cls.setup_logging()
        cls.setup_db()
        test_data_dir = os.environ['ANCHORE_ENGINE_TEST_HOME']
        cls.test_env = LocalTestDataEnvironment(data_dir=test_data_dir)


class NewDBPerTestUnitTest(BaseDBUnitTest):
    """
    Unit test where each test gets a freshly initialized database in-memory to ensure
    no overlap between tests.

    """
    @classmethod
    def setup_db(cls):
        print('No-op for db setup in class init')

    def setUp(self):
        print('Setting up new db connection')
        init_db()

    def tearDown(self):
        print('Tearing down db connection')
        self.disconnect()

    def disconnect(self):
        """
        Completely tear down the connection to force sqlite to refresh the db
        :return:
        """
        global ThreadLocalSession, Session, engine

        end_session()
        if ThreadLocalSession:
            ThreadLocalSession.close_all()
            ThreadLocalSession = None
        if Session:
            Session.close_all()
            Session = None

        if engine:
            engine.dispose()
            engine = None





