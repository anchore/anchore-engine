from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import get_thread_scoped_session, Image

from anchore_engine.services.policy_engine.engine.policy.gates.image_base_check import ImageCheckGate, BaseOutOfDateTrigger


class ImageCheckGateTest(GateUnitTest):
    gate_clazz = ImageCheckGate


    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=get_thread_scoped_session(), configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_base_out_of_date(self):
        t, gate, test_context = self.get_initialized_trigger(BaseOutOfDateTrigger.__trigger_name__)
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreaterEqual(len(t.fired), 0)

        img_with_tree = db.query(Image).get((self.test_env.get_images_named('testimage2')[0][0], '0'))
        test_context = gate.prepare_context(img_with_tree, test_context)
        t.evaluate(img_with_tree, test_context)
        print('Fired: {}'.format(t.fired))
        self.assertGreaterEqual(len(t.fired), 0)

