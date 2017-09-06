import logging
import os
import connexion
from flask_testing import TestCase

from test.services.policy_engine.utils import init_db, LocalTestDataEnvironment


class BaseTestCase(TestCase):
    swagger_path = '../../kirk/swagger/'
    api_yaml = 'swagger.yaml'
    test_env = LocalTestDataEnvironment(data_dir=os.environ['ANCHORE_ENGINE_TEST_HOME'])

    def init_env(self):
        init_db(connect_str=self.test_env.mk_db())
        logging.basicConfig(level=logging.INFO)

    def create_app(self):
        self.init_env()
        logging.getLogger('connexion.operation').setLevel('INFO')
        app = connexion.App(__name__, specification_dir=self.swagger_path)
        app.add_api(self.api_yaml)
        return app.app
