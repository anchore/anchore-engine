import json
import os
import time
import logging
import unittest
from anchore_engine.services.policy_engine.engine import logs
logs.test_mode = True
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask, FeedsUpdateTask
from legacy_test.services.policy_engine.utils import init_db, LocalTestDataEnvironment

logging.basicConfig(level='DEBUG')
log = get_logger()
test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TEST_HOME'])


class TestImageLoader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db(test_env.mk_db())
        test_env.init_feeds()

    def testFeedLoader(self):
        t = FeedsUpdateTask()
        t.execute()

    def testImageImport(self):
        log.setLevel(logging.ERROR)
        log.setLevel(logging.INFO)

        for f in test_env.image_exports():
            log.info('Testing image export loading into the db')

            with open(f[1]) as infile:
                json_data = json.load(infile)
                image_id = json_data[0]['image']['imagedata']['image_report']['meta']['imageId'] if type(json_data) == list else json_data['image_report']['meta']['imageId']
                log.info('Using image id: ' + image_id)

            t = time.time()
            task = ImageLoadTask(user_id='0', image_id=image_id, url='file:///' + f[1], force_reload=True)
            load_result = task.execute()
            load_duration = time.time() - t
            log.info('Load complete for {}. Took: {} sec for db load. Result: {}'.format(f, load_duration, load_result))
