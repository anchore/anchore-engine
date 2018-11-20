import unittest
import os
from anchore_engine.db import Image, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from legacy_test.services.policy_engine.utils import LocalTestDataEnvironment, init_db
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext


class GateUnitTest(unittest.TestCase):
    test_env = LocalTestDataEnvironment(data_dir=os.environ['ANCHORE_ENGINE_TEST_HOME'])
    __default_image__ = 'node'

    @classmethod
    def load_images_from_env(cls):
        for image_id, path in cls.test_env.image_exports():
            print(('Ensuring loaded: image id: {} from file: {}'.format(image_id, path)))
            t = ImageLoadTask(image_id=image_id, user_id='0', url='file://' + path)
            t.execute()

    @classmethod
    def setUpClass(cls):
        init_db(connect_str=cls.test_env.mk_db())
        cls.load_images_from_env()

        db = get_thread_scoped_session()
        cls.test_image = db.query(Image).get((cls.test_env.get_images_named(cls.__default_image__)[0][0], '0'))
        db.rollback()

    def get_initialized_trigger(self, trigger_name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(trigger_name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

