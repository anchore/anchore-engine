import unittest
import os
from anchore_engine.db import Image, get_thread_scoped_session
from test.services.policy_engine.utils import LocalTestDataEnvironment, init_db


class GateUnitTest(unittest.TestCase):
    test_env = LocalTestDataEnvironment(data_dir=os.environ['ANCHORE_ENGINE_TEST_HOME'])

    @classmethod
    def setUpClass(cls):
        init_db(connect_str=cls.test_env.mk_db())
        db = get_thread_scoped_session()
        cls.test_image = db.query(Image).get((cls.test_env.get_images_named('node')[0][0], '0'))
        db.rollback()
