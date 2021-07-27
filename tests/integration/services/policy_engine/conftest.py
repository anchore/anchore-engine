import os
from typing import Callable, List
from unittest.mock import MagicMock

import pytest

from anchore_engine.db import end_session
from anchore_engine.services.policy_engine import init_feed_registry
from anchore_engine.services.policy_engine.engine.feeds.config import (
    compute_selected_configs_to_sync,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import FeedSyncResult
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.services.policy_engine.engine.vulns.providers import LegacyProvider
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.utils import LocalTestDataEnvironment


def _init_te(init_feeds=True):
    init_feed_registry()
    t = LocalTestDataEnvironment(
        os.getenv("ANCHORE_TEST_DATA_ENV_DIR", "tests/data/test_data_env")
    )
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
        logger.info("Cleaning up after test env")
        end_session()


@pytest.fixture
def cls_test_data_env(anchore_db, request):
    request.cls.test_env = _init_te(True)


@pytest.fixture(scope="class")
def cls_test_data_env2(cls_anchore_db, request):
    request.cls.test_env = _init_te(True)


def _load_images(test_env):
    for img_id, path in test_env.image_exports():
        t = ImageLoadTask(user_id="0", image_id=img_id)
        t.fetch_url = "file://" + path
        t.execute()


def _load_image(name, test_env):
    logger.info("Loading image: {}".format(name))
    imgs = test_env.get_images_named(name)
    t = ImageLoadTask(user_id="0", image_id=imgs[0][0])
    t.fetch_url = "file://" + os.path.join(test_env.images_dir, imgs[0][1]["path"])
    t.execute()


@pytest.fixture()
def test_data_env_with_images_loaded(test_data_env):
    logger.info("Running test setup")

    _load_image("ruby", test_data_env)
    _load_image("node", test_data_env)

    test_env = test_data_env

    yield test_env

    logger.info("Ending db session")

    # Ensure the next init_db() call initializes fully
    end_session()


def run_legacy_sync(
    test_env: LocalTestDataEnvironment, to_sync: List[str]
) -> List[FeedSyncResult]:
    DataFeeds.__scratch_dir__ = "/tmp"
    feed_url = os.getenv("ANCHORE_GRYPE_DB_URL", "https://ancho.re/v1/service/feeds")
    data_clause = {}
    for feed_name in to_sync:
        data_clause[feed_name] = {"enabled": True, "url": feed_url}
    config = {
        "provider": "legacy",
        "sync": {
            "enabled": os.getenv("ANCHORE_FEEDS_ENABLED", True),
            "ssl_verify": os.getenv("ANCHORE_FEEDS_SSL_VERIFY", True),
            "connection_timeout_seconds": 3,
            "read_timeout_seconds": 60,
            "data": data_clause,
        },
    }
    vulnerabilities_provider = LegacyProvider()
    default_sync_config = vulnerabilities_provider.get_default_sync_config()
    sync_configs = compute_selected_configs_to_sync(
        provider="legacy",
        vulnerabilities_config=config,
        default_provider_sync_config=default_sync_config,
    )
    sync_utils = vulnerabilities_provider.get_sync_utils(sync_configs)
    sync_utils.get_client = MagicMock(return_value=test_env.feed_client)
    return DataFeeds.sync(sync_util_provider=sync_utils)


@pytest.fixture()
def run_legacy_sync_for_feeds(
    test_data_env,
) -> Callable[[List[str]], List[FeedSyncResult]]:
    test_env = test_data_env

    def run_legacy_sync_nested(to_sync: List[str]) -> List[FeedSyncResult]:
        return run_legacy_sync(test_env, to_sync)

    return run_legacy_sync_nested
