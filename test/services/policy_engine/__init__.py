import unittest
import os
from .utils import LocalTestDataEnvironment, init_db
from test import init_test_logging
from anchore_engine.services.policy_engine.engine import logs

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
        from anchore_engine.db.entities.common import sessionmaker, engine, ThreadLocalSession, end_session, disconnect
        end_session()
        disconnect()




