import os
import json
import unittest
import logging

from anchore_engine.services.policy_engine.engine.loaders import ImageLoader
from anchore_engine.db import get_thread_scoped_session, Image, end_session
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.gates.dockerfile import DockerfileGate
from legacy_test.services.policy_engine.utils import init_db, LocalTestDataEnvironment


class GateIntegrationTests(unittest.TestCase):
    test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TEST_HOME'])

    test_uri = 'sqlite:///:memory:'
    app = None
    test_gates = [
        {
            'gate': 'DOCKERFILECHECK',
            'trigger': 'EXPOSE',
            'action': 'GO',
            'params': {
                'ALLOWEDPORTS': '80,443',
                'DENIEDPORTS': '8080,22,21'
            }
        },
        {
            'gate': 'DOCKERFILECHECK',
            'trigger': 'NOFROM',
            'action': 'GO',
            'params': {}
        }
    ]

    @classmethod
    def setUpClass(cls):
        init_db(cls.test_uri)
        cls.load_test_data()
        logging.basicConfig(level=logging.DEBUG)

    @classmethod
    def load_test_data(cls):
        print('Loading test data')

        with open('data/trimmed_export_alpine.json') as f:
            img_json = json.load(f)

        loader = ImageLoader(img_json)
        img = loader.load()
        cls.img_id = img.id

        session = get_thread_scoped_session()
        session.add(img)
        session.commit()
        print('Done loading data')

    @classmethod
    def tearDownClass(cls):
        # Nothing to do since in-mem db
        end_session()

    def test_gate_builder(self):
        session = get_thread_scoped_session()
        eval_context = ExecutionContext(session, configuration={}, params={'ALLOWEDPORTS':'80,443'})
        img = session.query(Image).filter_by(id=self.img_id).scalar()
        t = DockerfileGate().get_trigger_named('ALLOWEDPORTS')
        print(('Start: {}'.format(json.dumps(g.json(), indent=2))))
        t.run(img, eval_context)
        print(('Result: {}'.format(json.dumps(g.json(), indent=2))))








