import json
import time

import pytest

from anchore_engine.configuration import localconfig
from anchore_engine.db import (
    FeedGroupMetadata,
    FeedMetadata,
    GemMetadata,
    Image,
    NpmMetadata,
    NvdMetadata,
    Vulnerability,
    session_scope,
)
from anchore_engine.services.policy_engine.engine.tasks import (
    FeedsUpdateTask,
    ImageLoadTask,
)
from anchore_engine.subsys import logger

logger.enable_test_logging()

localconfig.localconfig.update(
    {"feeds": {"sync_enabled": True, "selective_sync": {"enabled": False, "feeds": {}}}}
)


@pytest.mark.skip("Skipping due to long run time, will fix later")
def test_feed_task(test_data_env, anchore_db):

    logger.info("Running a feed sync with config: {}".format(localconfig.get_config()))
    t = FeedsUpdateTask()
    t.execute()

    with session_scope() as db:
        feeds = db.query(FeedMetadata).all()
        logger.info("{}".format(feeds))
        assert len(feeds) == 4  # packages, vulns, snyk, nvd

        feed_groups = db.query(FeedGroupMetadata).all()
        # See the tests/data/test_data_env/feeds dir for the proper count here
        logger.info("{}".format(feed_groups))
        assert len(feed_groups) == 11

        # ToDo: set the source data to a small number and make this an exact count
        assert db.query(Vulnerability).count() > 0
        assert db.query(NpmMetadata).count() > 0
        assert db.query(GemMetadata).count() > 0
        assert db.query(NvdMetadata).count() == 0


def test_image_load(test_data_env):
    for f in test_data_env.image_exports():
        logger.info("Testing image export loading into the db")

        with open(f[1]) as infile:
            json_data = json.load(infile)
            image_id = (
                json_data[0]["image"]["imagedata"]["image_report"]["meta"]["imageId"]
                if type(json_data) == list
                else json_data["image_report"]["meta"]["imageId"]
            )
            logger.info("Using image id: " + image_id)

        t = time.time()
        task = ImageLoadTask(
            user_id="0", image_id=image_id, url="file://" + f[1], force_reload=True
        )
        load_result = task.execute()
        load_duration = time.time() - t
        logger.info(
            "Load complete for {}. Took: {} sec for db load. Result: {}".format(
                f, load_duration, load_result
            )
        )

        with session_scope() as db:
            assert (
                db.query(Image).filter_by(id=image_id, user_id="0").one_or_none()
                is not None
            )
