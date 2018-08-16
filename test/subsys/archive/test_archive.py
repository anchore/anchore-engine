import os
import unittest
from anchore_engine.subsys import archive
from anchore_engine.subsys.object_store.exc import DriverConfigurationError, BadCredentialsError

test_key = os.getenv('TEST_ACCESS_KEY')
test_secret = os.getenv('TEST_SECRET_KEY')

class TestArchiveSubsys(unittest.TestCase):
    """
    Tests for the archive subsys. With each configured driver.
    """
    configs = {
        'fs': {},
        'db_legacy': {},
        'db': {},
        'swift': {},
        's3': {}
    }

    document_1 = '{"document": {"user_id": "admin", "final_action_reason": "policy_evaluation", "matched_whitelisted_images_rule": "matched_blacklisted_images_rule": false}}'
    document_json = {"user_id": "admin", "final_action_reason": "policy_evaluation",
                     "matched_whitelisted_images_rule": False, "created_at": 1522454550, "evaluation_problems": [],
                     "last_modified": 1522454550, "final_action": "stop",
                     "matched_mapping_rule": {"name": "default", "repository": "*",
                                              "image": {"type": "tag", "value": "*"},
                                              "whitelist_ids": ["37fd763e-1765-11e8-add4-3b16c029ac5c"],
                                              "registry": "*", "id": "c4f9bf74-dc38-4ddf-b5cf-00e9c0074611",
                                              "policy_id": "48e6f7d6-1765-11e8-b5f9-8b6f228548b6"},
                     "matched_blacklisted_images_rule": False}
    test_user_id = 'testuser1'
    test_bucket_id = 'testbucket1'

    @classmethod
    def setup_engine_config(cls, db_connect_str):
        """
        Sets the config for the service to bootstrap a specific db.
        :param db_connect_str:
        :return:
        """
        from anchore_engine.configuration import localconfig
        localconfig.load_defaults()
        localconfig.localconfig['credentials'] = {
            'database': {
                'db_connect': db_connect_str
            }
        }
        return localconfig.localconfig

    @classmethod
    def init_db(cls, connect_str='sqlite:///:memory:', do_bootstrap=True):
        """
        Policy-Engine specific db initialization and setup for testing.

        :param connect_str: connection string, defaults to sqllite in-memory if none provided
        :return:

        """
        conf = cls.setup_engine_config(connect_str)
        from anchore_engine.db import initialize, ArchiveDocument, Anchore, ObjectStorageRecord, ArchiveMetadata
        from anchore_engine.db.entities.common import do_create
        from anchore_engine.version import version, db_version
        initialize(versions={'service_version': version, 'db_version': db_version}, localconfig=conf) #, bootstrap_db=do_bootstrap)
        do_create(specific_tables=[ArchiveDocument.__table__, ArchiveMetadata.__table__, Anchore.__table__, ObjectStorageRecord.__table__])


    @classmethod
    def setUpClass(cls):
        cls.init_db()

    def test_config(self):
        """
        Test good and bad configurations for each driver
        :return:
        """
        pass

    def run_test(self):
        """
        Common test path for all configs to test against
        :return:
        """
        print('Basic string operations using get/put/delete')
        resp = archive.put(userId=self.test_user_id, bucket=self.test_bucket_id, archiveid='document_1',
                           data=self.document_1)
        print(('Document 1 PUT: {}'.format(resp)))

        resp = archive.get(userId=self.test_user_id,    bucket=self.test_bucket_id, archiveid='document_1')
        self.assertEqual(self.document_1, resp)

        self.assertTrue(archive.exists(self.test_user_id, self.test_bucket_id, 'document_1'))
        self.assertFalse(archive.exists(self.test_user_id, self.test_bucket_id, 'document_10'))

        print('Document operations')
        resp = archive.put_document(userId=self.test_user_id, bucket=self.test_bucket_id, archiveId='document_json',
                                    data=self.document_json)
        print(('Document JSON PUT Doc: {}'.format(resp)))

        resp = archive.get_document(userId=self.test_user_id, bucket=self.test_bucket_id, archiveId='document_json')
        print(('Document JSON GET Dock: {}'.format(resp)))
        self.assertEqual(self.document_json, resp)

        print('Document operations')
        resp = archive.put_document(userId=self.test_user_id, bucket=self.test_bucket_id, archiveId='document_json',
                                    data=self.document_1)
        print(('Document string PUT Doc: {}'.format(resp)))

        resp = archive.get_document(userId=self.test_user_id, bucket=self.test_bucket_id, archiveId='document_json')
        print(('Document string GET Dock: {}'.format(resp)))
        self.assertEqual(self.document_1, resp)

    def test_fs(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'localfs',
                    'config': {
                        'archive_data_dir': '/tmp/archive_test/fs_driver'
                    }
                }
            }
        }
        archive.initialize(config, force=True)
        self.run_test()

    def test_swift(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'swift',
                    'config': {
                        'user': 'test:tester',
                        'key': 'testing',
                        'auth': 'http://localhost:8080/auth/v1.0',
                        'container': 'testarchive'
                    }
                }
            }
        }

        archive.initialize(config, force=True)
        self.run_test()

    def test_swift_create_container(self):
        config = {
            'archive':{
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'swift',
                    'config': {
                        'user': 'test:tester',
                        'key': 'testing',
                        'auth': 'http://localhost:8080/auth/v1.0',
                        'container': 'testarchive2',
                        'create_container': True
                    }
                }
            }
        }

        archive.initialize(config, force=True)
        self.run_test()

    def test_swift_bad_creds(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'swift',
                    'config': {
                        'user': 'test:tester',
                        'key': 'testing123',
                        'auth': 'http://localhost:8080/auth/v1.0',
                        'container': 'testarchive'
                    }
                }
            }
        }

        with self.assertRaises(BadCredentialsError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))

    def test_swift_bad_container(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'swift',
                    'config': {
                        'user': 'test:tester',
                        'key': 'testing123',
                        'auth': 'http://localhost:8080/auth/v1.0',
                        'container': 'testarchive_does_not_exist'
                    }
                }
            }
        }

        with self.assertRaises(DriverConfigurationError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))

    def test_db(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': True
                },
                'storage_driver': {
                    'name': 'db2',
                    'config': {}
                }
            }
        }
        archive.initialize(config, force=True)
        self.run_test()

    def test_legacy_db(self):
        # NOTE: legacy db driver does not support compression since it uses string type instead of binary for content storage
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 'db',
                    'config': {}
                }
            }
        }

        archive.initialize(config, force=True)
        self.run_test()

    def test_s3(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'access_key': test_key,
                        'secret_key': test_secret,
                        'url': 'http://localhost:9000',
                        'region': None,
                        'bucket': 'testarchivebucket'
                    }
                }
            }
        }
        archive.initialize(config, force=True)
        self.run_test()

    def test_s3_create_bucket(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'create_bucket': True,
                        'access_key': test_key,
                        'secret_key': test_secret,
                        'url': 'http://localhost:9000',
                        'region': None,
                        'bucket': 'testarchivebucket2'
                    }
                }
            }
        }
        archive.initialize(config, force=True)
        self.run_test()

    def test_s3_bad_creds(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'access_key': test_key,
                        'secret_key': 'notrealkey',
                        'url': 'http://localhost:9000',
                        'region': None,
                        'bucket': 'testarchivebucket'
                    }
                }
            }
        }
        with self.assertRaises(BadCredentialsError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))

        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'access_key': test_key,
                        'secret_key': 'notrealkey',
                        'url': 'http://localhost:9000',
                        'region': None,
                        'bucket': 'testarchivebucket'
                    }
                }
            }
        }
        with self.assertRaises(BadCredentialsError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))

    def test_s3_bad_bucket(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'access_key': test_key,
                        'secret_key': test_secret,
                        'url': 'http://localhost:9000',
                        'region': None,
                        'bucket': 'testarchivebucket_does_not_exist'
                    }
                }
            }
        }
        with self.assertRaises(DriverConfigurationError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))

    def test_s3_auto(self):
        config = {
            'archive': {
                'compression': {
                    'enabled': False
                },
                'storage_driver': {
                    'name': 's3',
                    'config': {
                        'iamauto': True,
                        'bucket': 'testarchivebucket_does_not_exist'
                    }
                }
            }
        }
        with self.assertRaises(DriverConfigurationError) as err:
            archive.initialize(config, force=True)
        print(('Got expected error: {}'.format(err.exception.message)))
