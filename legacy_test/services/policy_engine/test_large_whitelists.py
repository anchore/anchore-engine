import unittest
import json
import copy
import logging
import time
import os

from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, ExecutableWhitelist
from anchore_engine.db import get_thread_scoped_session as get_session, Image
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from legacy_test.services.policy_engine import LocalTestDataEnvironment, init_db


class TestLargeBundlesEval(unittest.TestCase):
    invalid_empty_bundle = {}
    valid_empty_bundle = {
        'id': 'someid',
        'version': '1_0',
        'name': 'empty_bundle'

    }
    test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TEST_HOME'])

    @classmethod
    def setUpClass(cls):
        logging.basicConfig(level='INFO')
        init_db(cls.test_env.mk_db(), do_bootstrap=False)
        with open('test/data/bundle-large_whitelist.json') as f:
            cls.default_bundle = json.load(f)

    def load_images(self):
        img = self.test_env.get_images_named('node')[0][0]
        t = ImageLoadTask(user_id='0', image_id=img)
        t.execute()

    def testBasicEvaluation(self):
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/node:latest'
        built = build_bundle(self.default_bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)
        print(('Got: {}'.format(built)))

        db = get_session()
        img_obj = db.query(Image).get((self.test_env.get_images_named('node')[0][0], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print((json.dumps(evaluation.json(), indent=2)))
        print((json.dumps(evaluation.as_table_json(), indent=2)))

    @unittest.skip('b')
    def testWhitelists(self):
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/node:latest'

        [x for x in self.default_bundle['whitelists'] if x['id'] == 'wl_jessie'][0]['items'].append({'gate': 'ANCHORESEC', 'trigger_id': '*binutils*', 'id': 'testinserted123'})
        built = build_bundle(self.default_bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)
        print(('Got: {}'.format(built)))

        db = get_session()
        img_obj = db.query(Image).get((self.test_env.get_images_named('node')[0][0], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        t = time.time()
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print(('Evaluation: {}'.format(json.dumps(evaluation.json(), indent=2))))
        print(('Took: {}'.format(time.time() - t)))


        # Run without index handlers
        print('Running without optimized indexes')
        ExecutableWhitelist._use_indexes = False
        no_index_built = build_bundle(self.default_bundle, for_tag=test_tag)
        self.assertFalse(no_index_built.init_errors)
        print(('Got: {}'.format(no_index_built)))

        t = time.time()
        no_index_evaluation = no_index_built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        ExecutableWhitelist._use_indexes = True

        self.assertDictEqual(evaluation.json(), no_index_evaluation.json(), 'Index vs non-indexed returned different results')
        self.assertIsNotNone(no_index_evaluation, 'Got None eval')
        print(('Non-indexed Evaluation: {}'.format(json.dumps(evaluation.json(), indent=2))))
        print(('Non-indexed Evaluation Took: {}'.format(time.time() - t)))

    def testRegexes(self):
        """
        Test regular expressions in the trigger_id part of the WL rule
        :return:
        """
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/node:latest'

        bundle = copy.deepcopy(self.default_bundle)
        node_whitelist = [x for x in bundle['whitelists'] if x['id'] == 'wl_jessie'][0]
        node_whitelist['items'] = [x for x in node_whitelist['items'] if 'binutils' in x['trigger_id']]
        node_whitelist['items'].append(
            {'gate': 'ANCHORESEC', 'trigger_id': 'CVE-2016-6515+openssh-client', 'id': 'testinserted3'})
        node_whitelist['items'].append(
            {'gate': 'ANCHORESEC', 'trigger_id': 'CVE-2016-6515+*', 'id': 'test-cve-2016-6515'})
        node_whitelist['items'].append(
            {'gate': 'ANCHORESEC', 'trigger_id': 'CVE-2017*', 'id': 'testinserted2'})
        node_whitelist['items'].append(
            {'gate': 'ANCHORESEC', 'trigger_id': '*binutils*', 'id': 'testinserted1'})

        db = get_session()
        img_obj = db.query(Image).get((self.test_env.get_images_named('node')[0][0], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')

        ExecutableWhitelist._use_indexes = True
        built = build_bundle(bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)

        print('Executing with indexes')
        t = time.time()
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        t1 = time.time() - t
        print(('Took: {}'.format(t1)))
        self.assertIsNotNone(evaluation, 'Got None eval')

        ExecutableWhitelist._use_indexes = False
        non_index_built = build_bundle(bundle, for_tag=test_tag)
        self.assertFalse(non_index_built.init_errors)
        print('Executing without indexes')
        t2 = time.time()
        evaluation2 = non_index_built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        t2 = time.time() - t2
        print(('Took: {}'.format(t2)))
        self.assertIsNotNone(evaluation2, 'Got None eval')
        ExecutableWhitelist._use_indexes = True

        self.assertListEqual(evaluation.json()['bundle_decision']['policy_decisions'][0]['decisions'], evaluation2.json()['bundle_decision']['policy_decisions'][0]['decisions'])
        print(('Evaluation: {}'.format(json.dumps(evaluation.json(), indent=2))))
        open_ssl_wl_match = {
            "action": "go",
            "rule": {
              "action": "stop",
              "gate": "ANCHORESEC",
              "trigger": "VULNHIGH",
              "params": {}
            },
            "match": {
                "message": "HIGH Vulnerability found in package - openssh-client (CVE-2016-6515 - https://security-tracker.debian.org/tracker/CVE-2016-6515)",
                "trigger": "VULNHIGH",
                "whitelisted": {
                    "whitelist_id": "wl_jessie",
                    "matched_rule_id": "testinserted3",
                    "whitelist_name": "CVE whitelist for jessie - 12092017"
                },
                "trigger_id": "CVE-2016-6515+openssh-client"
            }
        }
        self.assertIn(open_ssl_wl_match, evaluation.json()['bundle_decision']['policy_decisions'][0]['decisions'])
        self.assertGreaterEqual(len([x for x in evaluation.json()['bundle_decision']['policy_decisions'][0]['decisions'] if x['match'].get('whitelisted',{}).get('matched_rule_id', '') in ['testinserted1', 'testinserted2', 'testinserted3']]), 1)