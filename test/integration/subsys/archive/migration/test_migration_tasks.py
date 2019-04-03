import pytest
from anchore_engine.subsys import archive
from anchore_engine.subsys.archive import migration
from anchore_engine.subsys import logger
from test.fixtures import anchore_db
from test.integration.subsys.archive.fixtures import s3_bucket, swift_container, test_swift_container, test_swift_auth_url, test_swift_user, test_swift_key, test_s3_bucket, test_s3_region, test_s3_url, test_s3_key, test_s3_secret_key

logger.enable_test_logging()

document_1 = b'{"document": {"user_id": "admin", "final_action_reason": "policy_evaluation", "matched_whitelisted_images_rule": "matched_blacklisted_images_rule": false}}'
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


def add_data():
    logger.info('Adding data')
    for i in range(0, 100):
        archiveId = 'doc-{}'.format(i)
        logger.info('Adding document: {}'.format(archiveId))
        archive.put_document(userId='test1', bucket='testing', archiveId=archiveId, data='TESTINGBUCKETDATASMALL'.join([str(x) for x in range(100)]))

def flush_data():
    logger.info('Flushing data')
    for i in range(0, 100):
        archiveId = 'doc-{}'.format(i)
        logger.info('Deleting document: {}'.format(archiveId))
        archive.delete_document(userId='test1', bucket='testing', archiveid=archiveId)

def run_test(src_client_config, dest_client_config):
    """
    Common test path for all configs to test against
    :return:
    """

    logger.info(('Running migration test from {} to {}'.format(src_client_config['name'], dest_client_config['name'])))
    archive.initialize({'services': {'catalog': {'archive': {'compression': {'enabled': False}, 'storage_driver': src_client_config}}}})
    add_data()

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

    flush_data()


def test_db_to_db2(anchore_db):
    from_config = {
        'name': 'db',
        'config': {}
    }

    to_config = {
        'name': 'db2',
        'config': {}
    }

    run_test(from_config, to_config)


def test_db_to_s3(s3_bucket, anchore_db):
    from_config = {
        'name': 'db',
        'config': {}
    }

    to_config = {
        'name': 's3',
        'config': {
            'access_key': test_s3_key,
            'secret_key': test_s3_secret_key,
            'url': test_s3_url,
            'region': test_s3_region,
            'bucket': test_s3_bucket
        }
    }

    run_test(from_config, to_config)
