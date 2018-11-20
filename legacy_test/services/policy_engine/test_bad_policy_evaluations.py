import json
import logging
import os

from anchore_engine.services.policy_engine.api.controllers.synchronous_operations import check_user_image_inline
from legacy_test.services.policy_engine.utils import init_db, LocalTestDataEnvironment

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

test_home = os.environ['ANCHORE_ENGINE_TESTING_HOME']
test_env = LocalTestDataEnvironment(data_dir=test_home)
test_env.init_feeds()


def init_db_persisted():
    global test_env
    init_db()

def run_bad_policy_test():
    init_db_persisted()
    b = test_env.get_bundle('bad_bundle1')
    img = list(test_env.image_map.keys())[0]
    print((json.dumps(check_user_image_inline(user_id='0', image_id=img, bundle=b, tag='docker.io/library/node:latest'), indent=2)))

if __name__ == '__main__':
    run_bad_policy_test()
