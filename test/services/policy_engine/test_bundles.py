import unittest
import json
import copy
import os
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, GateAction
from anchore_engine.db import get_thread_scoped_session as get_session, Image
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from test.services.policy_engine.utils import init_db, LocalTestDataEnvironment
from anchore_engine.services.policy_engine.engine.policy.exceptions import InitializationError, UnsupportedVersionError, BundleTargetTagMismatchError


class TestPolicyBundleEval(unittest.TestCase):
    invalid_empty_bundle = {}
    valid_empty_bundle = {
        'id': 'someid',
        'version': '1_0',
        'name': 'empty_bundle'

    }
    test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TEST_HOME'])

    test_image_ids = {
        'busybox': 'c75bebcdd211f41b3a460c7bf82970ed6c75acaab9cd4c9a4e125b03ca113798',
        'node': '6c792d9195914c8038f4cabd9356a5af47ead140b87682c8651edd55b010686c',
        'centos': '8140d0c64310d4e290bf3938757837dbb8f806acba0cb3f6a852558074345348',
        'ruby': 'f5cfccf111795cc67c1736df6ad1832afbd4842533b5a897d91e8d6122963657',
        'alpine': '02674b9cb179d57c68b526733adf38b458bd31ba0abff0c2bf5ceca5bad72cd9',
        'debian8': '4594f2fd77bf7ae4ad2b284a60e4eebb1a73b0859fe611b94f4245a6872d803e',
        'debian9': '3e83c23dba6a16cd936a3dc044df71b26706c5a4c28181bc3ca4a4af9f5f38ee',
        'fedora': '15895ef0b3b2b4e61bf03d38f82b42011ff7f226c681705a4022ae3d1d643888',
        'ubuntu:vivid-2015': '83fddfee12bbfa5f36494fbadd7d177dbf5c1b664461de1e6557ead030db13fb',
    }

    default_bundle = {}

    @classmethod
    def setUpClass(cls):
        init_db(cls.test_env.mk_db())
        cls.default_bundle = cls.test_env.get_bundle('default')

    def load_images(self):
        for img in self.test_image_ids.values():
            t = ImageLoadTask(user_id='0', image_id=img)
            t.execute()

    def testBasicEvaluation(self):
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/ruby:latest'
        built = build_bundle(self.default_bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)
        print('Got: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print(json.dumps(evaluation.json(), indent=2))
        print(json.dumps(evaluation.as_table_json(), indent=2))

    def testDuplicateRuleEvaluation(self):
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/ruby:latest'
        multi_gate_bundle = {
            'id': 'multigate1',
            'name': 'Multigate test1',
            'version': '1_0',
            'policies': [
                {
                    'id': 'policy1',
                    'name': 'Test policy1',
                    'version': '1_0',
                    'rules': [
                        {
                            'gate': 'DOCKERFILECHECK',
                            'trigger': 'FROMSCRATCH',
                            'params': [],
                            'action': 'GO'
                        },
                        {
                            'gate': 'DOCKERFILECHECK',
                            'trigger': 'FROMSCRATCH',
                            'params': [],
                            'action': 'STOP'
                        },
                        {
                            'action': 'stop',
                            'gate': 'DOCKERFILECHECK',
                            'trigger': 'DIRECTIVECHECK',
                            'params': [
                                {
                                    'name': 'DIRECTIVES',
                                    'value': 'RUN'
                                },
                                {
                                    'name': 'CHECK',
                                    'value': 'exists'
                                }
                            ]
                        },
                        {
                            'action': 'STOP',
                            'gate': 'DOCKERFILECHECK',
                            'trigger': 'DIRECTIVECHECK',
                            'params': [
                                {
                                    'name': 'DIRECTIVES',
                                    'value': 'USER'
                                },
                                {
                                    'name': 'CHECK',
                                    'value': 'not_exists'
                                }
                            ]
                        },
                        {
                            'action': 'STOP',
                            'gate': 'DOCKERFILECHECK',
                            'trigger': 'DIRECTIVECHECK',
                            'params': [
                                {
                                    'name': 'DIRECTIVES',
                                    'value': 'RUN'
                                },
                                {
                                    'name': 'CHECK',
                                    'value': '=',
                                    'check_value': 'yum update -y'
                                }
                            ]
                        }
                    ]
                }
            ],
            'whitelists': [],
            'mappings': [
                {
                    'registry': '*', 'repository': '*', 'image': {'type': 'tag', 'value': '*'}, 'policy_id': 'policy1', 'whitelist_ids': []
                }
            ]
        }
        built = build_bundle(multi_gate_bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)
        print('Got: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print(json.dumps(evaluation.json(), indent=2))
        print(json.dumps(evaluation.as_table_json(), indent=2))

    def test_image_whitelist(self):
        bundle = {
            'id': 'multigate1',
            'name': 'Multigate test1',
            'version': '1_0',
            'policies': [
                {
                    'id': 'policy1',
                    'name': 'Test policy1',
                    'version': '1_0',
                    'rules': [
                        {
                            'gate': 'always',
                            'trigger': 'always',
                            'params': [],
                            'action': 'STOP'
                        }
                    ]
                }
            ],
            'whitelists': [],
            'mappings': [
                {
                    'registry': '*', 'repository': '*', 'image': {'type': 'tag', 'value': '*'}, 'policy_id': 'policy1', 'whitelist_ids': []
                }
            ],
            'whitelisted_images': [
                {
                    'registry': '*',
                    'repository': '*',
                    'image': {
                        'type': 'tag',
                        'value': 'latest'
                    }
                }
            ],
            'blacklisted_images': []
        }

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        test_tag = 'docker.io/library/ruby:alpine'
        built = build_bundle(bundle, for_tag=test_tag)
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        self.assertIsNotNone(evaluation)
        self.assertEqual(GateAction.stop, evaluation.bundle_decision.final_decision)
        self.assertEqual('policy_evaluation', evaluation.bundle_decision.reason)

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        test_tag = 'docker.io/library/ruby:latest'
        built = build_bundle(bundle, for_tag=test_tag)
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        self.assertIsNotNone(evaluation)
        self.assertEqual(GateAction.go, evaluation.bundle_decision.final_decision)
        self.assertEqual('whitelisted', evaluation.bundle_decision.reason)

    def test_image_blacklist(self):
        bundle = {
            'id': 'multigate1',
            'name': 'Multigate test1',
            'version': '1_0',
            'policies': [
                {
                    'id': 'policy1',
                    'name': 'Test policy1',
                    'version': '1_0',
                    'rules': [
                        {
                            'gate': 'always',
                            'trigger': 'always',
                            'params': [],
                            'action': 'STOP'
                        }
                    ]
                }
            ],
            'whitelists': [],
            'mappings': [
                {
                    'registry': '*', 'repository': '*', 'image': {'type': 'tag', 'value': '*'}, 'policy_id': 'policy1', 'whitelist_ids': []
                }
            ],
            'blacklisted_images': [
                {
                    'registry': '*',
                    'repository': '*',
                    'image': {
                        'type': 'tag',
                        'value': 'latest'
                    }
                }
            ],
            'whitelisted_images': []
        }

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        test_tag = 'docker.io/library/ruby:alpine'
        built = build_bundle(bundle, for_tag=test_tag)
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        self.assertIsNotNone(evaluation)
        self.assertEqual(GateAction.stop, evaluation.bundle_decision.final_decision)
        self.assertEqual('policy_evaluation', evaluation.bundle_decision.reason)

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        test_tag = 'docker.io/library/ruby:latest'
        built = build_bundle(bundle, for_tag=test_tag)
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        self.assertIsNotNone(evaluation)
        self.assertEqual(GateAction.stop, evaluation.bundle_decision.final_decision)
        self.assertEqual('blacklisted', evaluation.bundle_decision.reason)

    def testWhitelists(self):
        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/ruby:latest'
        built = build_bundle(self.default_bundle, for_tag=test_tag)
        self.assertFalse(built.init_errors)
        print('Got: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print(json.dumps(evaluation.json(), indent=2))
        print(json.dumps(evaluation.as_table_json(), indent=2))

        to_whitelist = evaluation.bundle_decision.policy_decision.decisions[0]
        whitelist_bundle = copy.deepcopy(self.default_bundle)
        whitelist_bundle['whitelists'].append({
            'id': 'generated_whitelist1',
            'name': 'test_whitelist',
            'version': '1_0',
            'items': [
                {
                    'gate': to_whitelist.match.trigger.gate_cls.__gate_name__,
                    'trigger_id': to_whitelist.match.id,
                    'id': 'test_whitelistitem'
                }
            ]
        })

        whitelist_bundle['mappings'][0]['whitelist_ids'] = ['generated_whitelist1']
        built = build_bundle(whitelist_bundle, for_tag=test_tag)

        print('Got updated: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        #print(json.dumps(evaluation.json(), indent=2))
        #print(json.dumps(evaluation.as_table_json(), indent=2))

        self.assertNotIn(to_whitelist.match.id, map(lambda x: x.match.id if not (hasattr(x.match, 'is_whitelisted') and x.match.is_whitelisted) else None, evaluation.bundle_decision.policy_decision.decisions))

    def testErrorEvaluation(self):
        bundle = {
            'id': 'someid',
            'version': '1_0',
            'whitelists': [],
            'policies': [],
            'mappings': []
        }

        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/ruby:latest'
        built = build_bundle(bundle, for_tag=test_tag)
        print('Got: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))
        self.assertIsNotNone(evaluation, 'Got None eval')
        print('Result: {}'.format(json.dumps(evaluation.as_table_json(), indent=2)))

        with self.assertRaises(BundleTargetTagMismatchError) as f:
            evaluation = built.execute(img_obj, tag='docker.io/library/ubuntu:vivid-2015',
                                       context=ExecutionContext(db_session=db, configuration={}))

    def testDeprecatedGateEvaluation(self):
        bundle = {
            'id': 'someid',
            'version': '1_0',
            'whitelists': [],
            'policies': [
                {'id': 'abc',
                 'name': 'Deprecated Policy',
                 'version': '1_0',
                 'rules': [
                     {
                         'gate': 'PKGDIFF',
                         'trigger': 'pkgadd',
                         'params': [],
                         'action': 'stop'
                     },
                     {
                         'gate': 'always',
                         'trigger': 'always',
                         'action': 'go',
                         'params': []
                     }
                 ]
                 }
            ],
            'mappings': [
                {'registry': '*', 'repository': '*', 'image': {'type': 'tag', 'value': '*'}, 'name': 'Default', 'policy_id': 'abc', 'whitelist_ids': []}
            ]
        }

        print('Building executable bundle from default bundle')
        test_tag = 'docker.io/library/ruby:latest'
        with self.assertRaises(InitializationError) as ex:
            built = build_bundle(bundle, for_tag=test_tag)
            print('Got: {}'.format(built))

            db = get_session()
            img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
            if not img_obj:
                self.load_images()

            self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
            evaluation = built.execute(img_obj, tag=test_tag,
                                       context=ExecutionContext(db_session=db, configuration={}))

        built = build_bundle(bundle, for_tag=test_tag, allow_deprecated=True)
        print('Got: {}'.format(built))

        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        if not img_obj:
            self.load_images()

        self.assertIsNotNone(img_obj, 'Failed to get an image object to test')
        evaluation = built.execute(img_obj, tag=test_tag,
                                   context=ExecutionContext(db_session=db, configuration={}))

        self.assertIsNotNone(evaluation, 'Got None eval')
        print('Result: {}'.format(json.dumps(evaluation.json(), indent=2)))
        self.assertIsNotNone(evaluation.warnings)


    def testPolicyInitError(self):
        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))
        ruby_tag = 'dockerhub/library/ruby:latest'

        with self.assertRaises(UnsupportedVersionError) as f:
            built = build_bundle({
                'id':'someid',
                'version': 'invalid_version',
                'name': 'invalid_version',
                'whitelists': [],
                'policies': [],
                'mappings': []
                })
            built.execute(image_object=img_obj, context=None, tag=ruby_tag)

        with self.assertRaises(InitializationError) as f:
            built = build_bundle({
                'id':'someid',
                'version': '1_0',
                'name': 'invalid_version',
                'whitelists': [
                  {'id': 'whitelist1',
                   'version': 'invalid_version',
                   'name': 'bad whitelist',
                   'rules': []
                   }
                ],
                'policies': [
                    {
                        'id': 'ok_policy',
                        'version': 'v1.0',
                        'name': 'bad policy',
                        'rules': []
                    }
                ],
                'mappings': [
                    {'registry': '*',
                     'repository': '*',
                     'image': {'type': 'tag', 'value':'*'},
                     'policy_id': 'ok_policy',
                     'whitelist_ids': ['whitelist1']
                     }
                ]
                }, for_tag='dockerhub/library/centos:latest')
            built.execute(image_object=img_obj, context=None, tag='dockerhub/library/centos:latest')
        self.assertEqual(type(f.exception.causes[0]), UnsupportedVersionError)

        with self.assertRaises(InitializationError) as f:
            built = build_bundle({
                'id':'someid',
                'version': '1_0',
                'name': 'invalid_version',
                'whitelists': [
                  {'id': 'whitelist1',
                   'version': '1_0',
                   'name': 'okwhitelist',
                   'items': []
                   }
                ],
                'policies': [
                  {
                      'id': 'invalid_policy',
                      'version': 'invalid_version',
                      'name': 'bad policy',
                      'rules': []
                  }
                ],
                'mappings': [
                    {'registry': '*',
                     'repository': '*',
                     'image': {'type': 'tag', 'value':'*'},
                     'policy_id': 'invalid_policy',
                     'whitelist_ids': ['whitelist1']
                     }
                ]
                }, for_tag='dockerhub/library/centos:latest')
            built.execute(image_object=img_obj, context=None, tag='dockerhub/library/centos:latest')
        self.assertEqual(type(f.exception.causes[0]), UnsupportedVersionError)

        with self.assertRaises(InitializationError) as f:
            built = build_bundle({
                'id':'someid',
                'version': '1_0',
                'name': 'invalid_version',
                'whitelists': [
                      {'id': 'whitelist1',
                       'version': '1_0',
                       'name': 'ok whitelist',
                       'items': []
                       }
                ],
                'policies': [
                    {
                      'id': 'okpolicy',
                      'version': '2_0',
                      'name': 'ok policy',
                      'rules': []
                    }
                ],
                'mappings': [
                    {
                        'id': 'invalid_mapping',
                        'policy_id': 'okpolicy',
                        'whitelist_ids': ['whitelist1'],
                        'registry': '*',
                        'repository': '*',
                        'image': {
                            'type': 'tag',
                            'value': '*'
                        }

                    }
                ]
            })
            built.execute(image_object=img_obj, context=None, tag=ruby_tag)
        self.assertEqual(type(f.exception.causes[0]), UnsupportedVersionError)

    def testPolicyNotFound(self):
        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))

        with self.assertRaises(InitializationError) as f:
            built = build_bundle(self.test_env.get_bundle('bad_policy_id'))
            built.execute(image_object=img_obj, context=None, tag='dockerhub/library/ruby:latest')
            print('Expected Initialization error: {}'.format(f.exception))

    def testInvalidActions(self):
        db = get_session()
        img_obj = db.query(Image).get((self.test_image_ids['ruby'], '0'))

        with self.assertRaises(InitializationError) as f:
            built = build_bundle(self.test_env.get_bundle('bad_bundle1'))
            built.execute(image_object=img_obj, context=None, tag='dockerhub/library/ruby:latest')
            built.execute(image_object=img_obj, context=None, tag='test')

        with self.assertRaises(InitializationError) as f:
            built = build_bundle({
                'id': 'someid',
                'version': '1_0',
                'name': 'invalid_actions',
                'whitelists': [
                    {'id': 'whitelist1',
                     'version': '1_0',
                     'name': 'ok whitelist',
                     'items': []
                     }
                ],
                'policies': [
                    {
                        'id': 'okpolicy',
                        'version': '1_0',
                        'name': 'ok policy',
                        'rules': [
                            {
                                'gate': 'ANCHORESEC',
                                'trigger': 'UNSUPPPORTEDDISTRO',
                                'action': 'HELLO',
                                'params': []
                            }
                        ]
                    }
                ],
                'mappings': [
                    {
                        'policy_id': 'okpolicy',
                        'whitelist_ids': ['whitelist1'],
                        'registry': '*',
                        'repository': '*',
                        'image': {
                            'type': 'tag',
                            'value': '*'
                        }

                    }
                ]
            })
            built.execute(image_object=img_obj, context=None, tag=None)

        with self.assertRaises(InitializationError) as f:
            bad_param1 = build_bundle({
                'id': 'someid',
                'version': '1_0',
                'name': 'invalid_params',
                'whitelists': [
                    {'id': 'whitelist1',
                     'version': '1_0',
                     'name': 'ok whitelist',
                     'items': []
                     }
                ],
                'policies': [
                    {
                        'id': 'okpolicy',
                        'version': '1_0',
                        'name': 'ok policy',
                        'rules': [
                            {
                                'gate': 'ANCHORESEC',
                                'trigger': 'FEEDOUTOFDATE',
                                'action': 'GO',
                                'params': [
                                    {
                                        'name': 'MAXAGE',
                                        'value': 0.1
                                    }
                                ]
                            }
                        ]
                    }
                ],
                'mappings': [
                    {
                        'policy_id': 'okpolicy',
                        'whitelist_ids': ['whitelist1'],
                        'registry': '*',
                        'repository': '*',
                        'image': {
                            'type': 'tag',
                            'value': '*'
                        }

                    }
                ]
            })
            built.execute(image_object=img_obj, context=None, tag=None)


        with self.assertRaises(InitializationError) as f:
            bad_param2 = build_bundle({
                'id': 'someid',
                'version': '1_0',
                'name': 'invalid_params',
                'whitelists': [
                    {'id': 'whitelist1',
                     'version': '1_0',
                     'name': 'ok whitelist',
                     'items': []
                     }
                ],
                'policies': [
                    {
                        'id': 'okpolicy',
                        'version': '1_0',
                        'name': 'ok policy',
                        'rules': [
                            {
                                'gate': 'ANCHORESEC',
                                'trigger': 'FEEDOUTOFDATE',
                                'action': 'GO',
                                'params': [
                                    {
                                        'name': 'MAXIMUS_AGIMUS',
                                        'value': 10
                                    }
                                ]
                            }
                        ]
                    }
                ],
                'mappings': [
                    {
                        'policy_id': 'okpolicy',
                        'whitelist_ids': ['whitelist1'],
                        'registry': '*',
                        'repository': '*',
                        'image': {
                            'type': 'tag',
                            'value': '*'
                        }

                    }
                ]
            })
            built.execute(image_object=img_obj, context=None, tag=None)
