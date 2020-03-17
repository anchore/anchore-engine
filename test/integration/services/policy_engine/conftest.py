import os
import pytest

from anchore_engine.subsys import logger
from test.integration.services.policy_engine.utils import LocalTestDataEnvironment
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.db import end_session
from test.fixtures import anchore_db, cls_anchore_db

def _init_te(init_feeds=True):
    t = LocalTestDataEnvironment(os.getenv('ANCHORE_TEST_DATA_ENV_DIR', 'test/data/test_data_env'))
    if init_feeds:
        t.init_feeds()

    return t

@pytest.fixture
def test_data_env(anchore_db):
    """
    Fixture for a test data env
    :param anchore_db:
    :return:
    """
    try:
        te = _init_te(True)
        yield te
    finally:
        logger.info('Cleaning up after test env')
        end_session()


@pytest.fixture
def cls_test_data_env(anchore_db, request):
    request.cls.test_env = _init_te(True)


@pytest.fixture(scope='class')
def cls_test_data_env2(cls_anchore_db, request):
    request.cls.test_env = _init_te(True)


def _load_images(test_env):
    for img_id, path in test_env.image_exports():
        t = ImageLoadTask(user_id='0', image_id=img_id)
        t.fetch_url = 'file://' + path
        t.execute()


def _load_image(name, test_env):
    logger.info('Loading image: {}'.format(name))
    imgs = test_env.get_images_named(name)
    t = ImageLoadTask(user_id='0', image_id=imgs[0][0])
    t.fetch_url = 'file://' + os.path.join(test_env.images_dir, imgs[0][1]['path'])
    t.execute()


@pytest.fixture()
def test_data_env_with_images_loaded(test_data_env):
    logger.info('Running test setup')

    _load_image('ruby', test_data_env)
    _load_image('node', test_data_env)

    test_env = test_data_env

    yield test_env

    logger.info('Ending db session')

    # Ensure the next init_db() call initializes fully
    end_session()