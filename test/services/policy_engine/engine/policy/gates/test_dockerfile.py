"""
Gate Unit tests
"""

from test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import Image

from anchore_engine.services.policy_engine.engine.policy.gates.dockerfile import DockerfileGate, NoHealthCheck, NoDockerfile, NoFromTrigger, NoTag, FromScratch, ExposeTrigger, Sudo, VolumePresent

test_image = Image()
test_image.distro_name = 'debian'
test_image.distro_version = '9'
test_image.user_id = '0'
test_image.layer_info_json = ['layer1', 'layer2']
test_image.dockerfile_contents = 'FROM SCRATCH\nHEALTHCHECK blah\n'
test_image.dockerfile_mode = 'Guessed'

dockerfile_from = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_scratch = 'FROM SCRATCH\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_healthcheck = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\nHEALTHCHECK echo hello\n'
dockerfile_no_healthcheck = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_no_tag = 'FROM library/centos\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_no_from = 'ADD ./files/* /\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_sudo = 'FROM library/centos\nRUN sudo apt-get install\nCMD echo helloworld\n'
dockerfile_volume = 'FROM library/centos\nRUN sudo apt-get install\nVOLUME /var/log\nCMD echo helloworld\n'
dockerfile_expose = 'FROM library/centos\nRUN sudo apt-get install\nEXPOSE 8000\nVOLUME /var/log\nCMD echo helloworld\n'


class DockerfileGateTest(GateUnitTest):
    gate_clazz = DockerfileGate

    def get_initialized_trigger(self, name, config=None, **kwargs):
        clazz = self.gate_clazz.get_trigger_named(name)
        trigger = clazz(self.gate_clazz, **kwargs)
        context = ExecutionContext(db_session=None, configuration=config)
        gate = trigger.gate_cls()

        return trigger, gate, context

    def test_healthcheck(self):
        t, gate, test_context = self.get_initialized_trigger(NoHealthCheck.__trigger_name__)
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format(t.fired))

    def test_nodockerfile(self):
        t, gate, test_context = self.get_initialized_trigger(NoDockerfile.__trigger_name__)
        test_image.dockerfile_contents = ''
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))

    def test_nofromtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(NoFromTrigger.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_no_from
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))

    def test_notagtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(NoTag.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_no_tag
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))

    def test_fromscratchtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(FromScratch.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_scratch
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))

    def test_exposetrigger(self):
        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, ALLOWEDPORTS='8000')
        test_image.dockerfile_contents = dockerfile_expose
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))
        self.assertEqual(len(t.fired), 0)

        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, ALLOWEDPORTS='80')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, DENIEDPORTS='8000', ALLOWEDPORTS='80,8080')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))
        self.assertEqual(len(t.fired), 2)

    def test_sudotrigger(self):
        t, gate, test_context = self.get_initialized_trigger(Sudo.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_sudo
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))

    def test_volumepresenttrigger(self):
        t, gate, test_context = self.get_initialized_trigger(VolumePresent.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_volume
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print('Fired: {}'.format([x.json() for x in t.fired]))


