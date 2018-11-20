"""
Gate Unit tests
"""

from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import Image

from anchore_engine.services.policy_engine.engine.policy.gates.dockerfile import DockerfileGate, \
    ExposedPortsTrigger, \
    InstructionCheckTrigger, \
    EffectiveUserTrigger, \
    NoDockerfile

test_image = Image()
test_image.distro_name = 'debian'
test_image.distro_version = '9'
test_image.user_id = '0'
test_image.layer_info_json = ['layer1', 'layer2']
test_image.dockerfile_contents = 'FROM SCRATCH\nHEALTHCHECK blah\n'
test_image.dockerfile_mode = 'Guessed'

dockerfile_from = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_scratch = 'FROM SCRATCH\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_healthcheck = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\nHEALTHcheck echo hello\n'
dockerfile_no_healthcheck = 'FROM library/centos:latest\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_no_tag = 'FROM library/centos\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_no_from = 'ADD ./files/* /\nRUN apt-get install\nCMD echo helloworld\n'
dockerfile_sudo = 'FROM library/centos\nRUN sudo apt-get install\nCMD echo helloworld\n'
dockerfile_volume = 'FROM library/centos\nRUN sudo apt-get install\nVOLUME /var/log\nCMD echo helloworld\n'
dockerfile_expose = 'FROM library/centos\nRUN sudo apt-get install\nEXPOSE 8000\nVOLUME /var/log\nCMD echo helloworld\n'


class DockerfileGateTest(GateUnitTest):
    gate_clazz = DockerfileGate


    def test_nodockerfile(self):
        t, gate, test_context = self.get_initialized_trigger(NoDockerfile.__trigger_name__)
        test_image.dockerfile_contents = ''
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))


    def test_exposetrigger(self):
        t, gate, test_context = self.get_initialized_trigger(ExposedPortsTrigger.__trigger_name__, ports='8000', type='whitelist')
        test_image.dockerfile_contents = dockerfile_expose
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(0, len(t.fired))

        t, gate, test_context = self.get_initialized_trigger(ExposedPortsTrigger.__trigger_name__, ports='80', type='whitelist')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(1, len(t.fired))

        t, gate, test_context = self.get_initialized_trigger(ExposedPortsTrigger.__trigger_name__, type='blacklist', ports='80,8000')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(1, len(t.fired))


    def test_directivechecktrigger_exists(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='COPY', check='exists')
        test_image.dockerfile_contents = 'COPY /root /rootcmd\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='COPY', check='exists')
        test_image.dockerfile_contents = 'RUN echo hello\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)

    def test_directivechecktrigger_notexists(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='COPY', check='not_exists')
        test_image.dockerfile_contents = 'COPY /root /rootcmd\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='COPY', check='not_exists')
        test_image.dockerfile_contents = 'RUN echo "root hello copy 123"\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))


    def test_directivechecktrigger_equals(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='RUN', check='=', value='yum update -y')
        test_image.dockerfile_contents = 'RUN yum update -y\nENV abs\nCMD echo hi\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directivechecktrigger_notequals(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='RUN', check='!=', value='testvalue')
        test_image.dockerfile_contents = 'RUN yum update -y\nENV abs\nCMD echo hi\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_instructionchecktrigger_like(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='like', value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nUSER testuser123\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='like', value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nUSER test_user\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_instructionchecktrigger_notlike(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='not_like', value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='not_like', value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_instructionchecktrigger_in(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='in', value='testuser,someuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='in', value='root,someuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_instructionchecktrigger_notin(self):
        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='not_in', value='root')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(InstructionCheckTrigger.__trigger_name__, instruction='USER', check='not_in', value='root,testuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))


    def test_effectiveuser_trigger(self):
        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='root', type='whitelist')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='testuser', type='whitelist')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(0, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='testuser', type='whitelist')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='root', type='blacklist')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='testuser', type='blacklist')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='testuser', type='blacklist')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='testuser, nginx', type='blacklist')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(0, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='nginx', type='blacklist')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER nginx\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(1, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='user1', type='whitelist')
        test_image.dockerfile_contents = 'USER [testuser]\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(1, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='user1', type='whitelist')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(1, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='user1', type='whitelist')
        test_image.dockerfile_contents = 'USER user1\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(0, len(t.fired))
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, users='user1', type='whitelist')
        test_image.dockerfile_contents = 'USER [user1]\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))







