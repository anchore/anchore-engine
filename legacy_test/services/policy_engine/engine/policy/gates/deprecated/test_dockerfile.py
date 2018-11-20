"""
Gate Unit tests
"""

from legacy_test.services.policy_engine.engine.policy.gates import GateUnitTest
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext
from anchore_engine.db import Image

from anchore_engine.services.policy_engine.engine.policy.gates.deprecated.dockerfile import DockerfileGate, \
    NoHealthCheck, \
    NoDockerfile, \
    NoFromTrigger, \
    NoTag, \
    FromScratch, \
    ExposeTrigger, \
    Sudo, \
    VolumePresent, \
    DirectiveCheckTrigger, \
    EffectiveUserTrigger

test_image = Image()
test_image.distro_name = 'debian'
test_image.distro_version = '9'
test_image.user_id = '0'
test_image.layer_info_json = ['layer1', 'layer2']
test_image.dockerfile_contents = 'FROM SCRATCH\nHEALTHcheck blah\n'
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
        print(('Fired: {}'.format(t.fired)))

    def test_nodockerfile(self):
        t, gate, test_context = self.get_initialized_trigger(NoDockerfile.__trigger_name__)
        test_image.dockerfile_contents = ''
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_nofromtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(NoFromTrigger.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_no_from
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_notagtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(NoTag.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_no_tag
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_fromscratchtrigger(self):
        t, gate, test_context = self.get_initialized_trigger(FromScratch.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_scratch
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_exposetrigger(self):
        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, allowedports='8000')
        test_image.dockerfile_contents = dockerfile_expose
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(0, len(t.fired))

        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, allowedports='80')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(ExposeTrigger.__trigger_name__, deniedports='8000', allowedports='80,8080')
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))
        self.assertEqual(len(t.fired), 2)

    def test_sudotrigger(self):
        t, gate, test_context = self.get_initialized_trigger(Sudo.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_sudo
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_volumepresenttrigger(self):
        t, gate, test_context = self.get_initialized_trigger(VolumePresent.__trigger_name__)
        test_image.dockerfile_contents = dockerfile_volume
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directivechecktrigger_exists(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='COPY', check='exists')
        test_image.dockerfile_contents = 'COPY /root /rootcmd\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='COPY', check='exists')
        test_image.dockerfile_contents = 'RUN echo hello\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)

    def test_directivechecktrigger_notexists(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='COPY', check='not_exists')
        test_image.dockerfile_contents = 'COPY /root /rootcmd\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='COPY', check='not_exists')
        test_image.dockerfile_contents = 'RUN echo "root hello copy 123"\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))


    def test_directivechecktrigger_equals(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='RUN', check='=', check_value='yum update -y')
        test_image.dockerfile_contents = 'RUN yum update -y\nENV abs\nCMD echo hi\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directivechecktrigger_notequals(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='RUN', check='!=', check_value='testvalue')
        test_image.dockerfile_contents = 'RUN yum update -y\nENV abs\nCMD echo hi\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directiveschecktrigger_like(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='like', check_value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nUSER testuser123\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='like', check_value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nUSER test_user\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directiveschecktrigger_notlike(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='not_like', check_value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='not_like', check_value='testuser.*')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directiveschecktrigger_in(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='in', check_value='testuser,someuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='in', check_value='root,someuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_directiveschecktrigger_notin(self):
        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='not_in', check_value='root')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(DirectiveCheckTrigger.__trigger_name__, directives='USER', check='not_in', check_value='root,testuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))


    def test_effectiveuser_trigger(self):
        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='root')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='testuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='testuser')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='root')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='testuser')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='testuser')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='testuser', allowed='nginx')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='testuser', allowed='nginx')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER nginx\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, denied='root', allowed='root')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER root\n'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='user1')
        test_image.dockerfile_contents = 'USER [testuser]\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='user1')
        test_image.dockerfile_contents = 'USER testuser\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='user1')
        test_image.dockerfile_contents = 'USER user1\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='user1')
        test_image.dockerfile_contents = 'USER [user1]\nRUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi'
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        print(('Fired: {}'.format([x.json() for x in t.fired])))

    def test_context_prep_badlines(self):
        t, gate, test_context = self.get_initialized_trigger(EffectiveUserTrigger.__trigger_name__, allowed='root')
        test_image.dockerfile_contents = 'RUN apt-get install blah1 balh2 blah2 testuser1\nRUN echo hi\nUSER testuser\n|10 BUILD=blahblah\nsingleline\nsingleline\n\n'

        test_context = gate.prepare_context(test_image, test_context)
        print('Properly did not raise exception')



