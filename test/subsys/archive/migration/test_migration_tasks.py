import unittest
from anchore_engine.subsys import archive
from anchore_engine.subsys.archive import migration
from anchore_engine.subsys import logger

logger.enable_bootstrap_logging('testing')

class TestArchiveMigrations(unittest.TestCase):
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
        from anchore_engine.db import initialize, ArchiveDocument, Anchore, ObjectStorageRecord, ArchiveMetadata, ArchiveMigrationTask, Task
        from anchore_engine.db.entities.common import do_create
        from anchore_engine.version import version, db_version
        initialize(versions={'service_version': version, 'db_version': db_version}, localconfig=conf) #, bootstrap_db=do_bootstrap)
        do_create(specific_tables=[ArchiveDocument.__table__, ArchiveMetadata.__table__, Anchore.__table__, ObjectStorageRecord.__table__, Task.__table__, ArchiveMigrationTask.__table__])

    @classmethod
    def setUpClass(cls):
        cls.init_db()

    def add_data(self):
        print('Adding data')
        for i in range(0, 100):
            archiveId = 'doc-{}'.format(i)
            print(('Adding document: {}'.format(archiveId)))
            archive.put_document(userId='test1', bucket='testing', archiveId=archiveId, data='TESTINGBUCKETDATASMALL'.join([str(x) for x in range(100)]))

    def flush_data(self):
        print('Flushing data')
        for i in range(0, 100):
            archiveId = 'doc-{}'.format(i)
            print(('Deleting document: {}'.format(archiveId)))
            archive.delete_document(userId='test1', bucket='testing', archiveid=archiveId)

    def run_test(self, src_client_config, dest_client_config):
        """
        Common test path for all configs to test against
        :return:
        """

        print(('Running migration test from {} to {}'.format(src_client_config['name'], dest_client_config['name'])))
        archive.initialize({'services': {'catalog': {'archive': {'compression': {'enabled': False}, 'storage_driver': src_client_config}}}})
        self.add_data()

        src_config = {
            'storage_driver': src_client_config,
            'compression': {
                'enabled': False
            }
        }

        dest_config = {
            'storage_driver': dest_client_config,
            'compression': {
                'enabled': False
            }
        }

        migration.initiate_migration(src_config, dest_config, remove_on_source=True, do_lock=False)

        self.flush_data()

    def test_db_to_db2(self):
        from_config = {
            'name': 'db',
            'config': {}
        }

        to_config = {
            'name': 'db2',
            'config': {}
        }

        self.run_test(from_config, to_config)

    def test_db_to_s3(self):
        from_config = {
            'name': 'db',
            'config': {}
        }

        to_config = {
            'name': 's3',
            'config': {
                'access_key': '9EB92C7W61YPFQ6QLDOU',
                'secret_key': 'TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s',
                'url': 'http://localhost:9000',
                'region': None,
                'bucket': 'testarchivebucket'
            }
        }

        self.run_test(from_config, to_config)
