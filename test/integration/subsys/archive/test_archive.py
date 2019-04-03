"""
Tests for the archive subsys. With each configured driver.
"""

import os
import pytest
from anchore_engine.subsys import archive
from anchore_engine.subsys.object_store.exc import DriverConfigurationError, BadCredentialsError
from test.fixtures import anchore_db
from .fixtures import swift_container, s3_bucket, test_s3_secret_key, test_s3_key, test_s3_bucket, test_s3_url, test_s3_region, test_swift_auth_url, test_swift_container, test_swift_key, test_swift_user
from anchore_engine.subsys import logger

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

disable_tests = False

def run_test():
    """
    Common test path for all configs to test against
    :return:
    """
    logger.info('Basic string operations using get/put/delete')
    resp = archive.put(userId=test_user_id, bucket=test_bucket_id, archiveid='document_1', data=document_1)
    logger.info('Document 1 PUT: {}'.format(resp))

    resp = archive.get(userId=test_user_id,    bucket=test_bucket_id, archiveid='document_1')
    assert document_1 == resp

    assert archive.exists(test_user_id, test_bucket_id, 'document_1')
    assert not archive.exists(test_user_id, test_bucket_id, 'document_10')

    logger.info('Document operations')
    resp = archive.put_document(userId=test_user_id, bucket=test_bucket_id, archiveId='document_json', data=document_json)
    logger.info('Document JSON PUT Doc: {}'.format(resp))

    resp = archive.get_document(userId=test_user_id, bucket=test_bucket_id, archiveId='document_json')
    logger.info('Document JSON GET Dock: {}'.format(resp))
    assert document_json == resp

    logger.info('Document operations')
    resp = archive.put_document(userId=test_user_id, bucket=test_bucket_id, archiveId='document_json', data=document_1.decode('utf-8'))
    logger.info('Document string PUT Doc: {}'.format(resp))

    resp = archive.get_document(userId=test_user_id, bucket=test_bucket_id, archiveId='document_json')
    logger.info('Document string GET Dock: {}'.format(resp))
    assert document_1.decode('utf-8') == resp


def test_noop(anchore_db):
    pass

@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_fs(anchore_db):
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
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_swift(swift_container, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': True
            },
            'storage_driver': {
                'name': 'swift',
                'config': {
                    'user': test_swift_user,
                    'key': test_swift_key,
                    'auth': test_swift_auth_url,
                    'container': test_swift_container
                }
            }
        }
    }

    archive.initialize(config, force=True)
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_swift_create_container(swift_container, anchore_db):
    config = {
        'archive':{
            'compression': {
                'enabled': True
            },
            'storage_driver': {
                'name': 'swift',
                'config': {
                    'user': test_swift_user,
                    'key': test_swift_key,
                    'auth': test_swift_auth_url,
                    'container': 'testarchive2',
                    'create_container': True
                }
            }
        }
    }

    archive.initialize(config, force=True)
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_swift_bad_creds(swift_container, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': True
            },
            'storage_driver': {
                'name': 'swift',
                'config': {
                    'user': test_swift_user,
                    'key': 'badkey',
                    'auth': test_swift_auth_url,
                    'container': test_swift_container
                }
            }
        }
    }

    with pytest.raises(BadCredentialsError) as err:
        archive.initialize(config, force=True)
        pytest.fail('Should have raised bad creds exception on init')

    logger.info('Got expected error: {}'.format(err.type))


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_swift_bad_container(swift_container, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': True
            },
            'storage_driver': {
                'name': 'swift',
                'config': {
                    'user': test_swift_user,
                    'key': test_swift_key,
                    'auth': test_swift_auth_url,
                    'container': 'testarchive_does_not_exist'
                }
            }
        }
    }

    with pytest.raises(DriverConfigurationError) as err:
        archive.initialize(config, force=True)

    logger.info('Got expected error: {}'.format(err.type))


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_db(anchore_db):
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
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_legacy_db(anchore_db):
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
    run_test()

@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_s3(s3_bucket, anchore_db):
    logger.info('Creds: {} / {}'.format(test_s3_key, test_s3_secret_key))
    config = {
        'archive': {
            'compression': {
                'enabled': False
            },
            'storage_driver': {
                'name': 's3',
                'config': {
                    'access_key': test_s3_key,
                    'secret_key': test_s3_secret_key,
                    'url': test_s3_url,
                    'region': test_s3_region,
                    'bucket': test_s3_bucket
                }
            }
        }
    }
    archive.initialize(config, force=True)
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_s3_create_bucket(s3_bucket, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': False
            },
            'storage_driver': {
                'name': 's3',
                'config': {
                    'create_bucket': True,
                    'access_key': test_s3_key,
                    'secret_key': test_s3_secret_key,
                    'url': test_s3_url,
                    'region': test_s3_region,
                    'bucket': 'testarchivebucket2'
                }
            }
        }
    }
    archive.initialize(config, force=True)
    run_test()


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_s3_bad_creds(s3_bucket, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': False
            },
            'storage_driver': {
                'name': 's3',
                'config': {
                    'access_key': test_s3_key,
                    'secret_key': 'notrealkey',
                    'url': test_s3_url,
                    'region': test_s3_region,
                    'bucket': test_s3_bucket
                }
            }
        }
    }
    with pytest.raises(BadCredentialsError) as err:
        archive.initialize(config, force=True)
        pytest.fail('Should have gotten a bad creds error')

    logger.info('Got expected error: {}'.format(err.type))

    config = {
        'archive': {
            'compression': {
                'enabled': False
            },
            'storage_driver': {
                'name': 's3',
                'config': {
                    'access_key': test_s3_key,
                    'secret_key': 'notrealkey',
                    'url': test_s3_url,
                    'region': test_s3_region,
                    'bucket': test_s3_bucket
                }
            }
        }
    }
    with pytest.raises(BadCredentialsError) as err:
        archive.initialize(config, force=True)
        pytest.fail('Should have gotten a bad creds error')

    logger.info('Got expected error: {}'.format(err.type))


@pytest.mark.skipif(disable_tests, reason='skipped by config')
def test_s3_bad_bucket(s3_bucket, anchore_db):
    config = {
        'archive': {
            'compression': {
                'enabled': False
            },
            'storage_driver': {
                'name': 's3',
                'config': {
                    'access_key': test_s3_key,
                    'secret_key': test_s3_secret_key,
                    'url': test_s3_url,
                    'region': None,
                    'bucket': 'testarchivebucket_does_not_exist'
                }
            }
        }
    }
    with pytest.raises(DriverConfigurationError) as err:
        archive.initialize(config, force=True)
    logger.info('Got expected error: {}'.format(err.type))


@pytest.mark.skip #if(disable_tests, reason='skipped by config')
def test_s3_auto(s3_bucket, anchore_db):
    os.environ['AWS_ACCESS_KEY'] = test_s3_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = test_s3_secret_key

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
    with pytest.raises(DriverConfigurationError) as err:
        archive.initialize(config, force=True)
    logger.info('Got expected error: {}'.format(err.typee))
