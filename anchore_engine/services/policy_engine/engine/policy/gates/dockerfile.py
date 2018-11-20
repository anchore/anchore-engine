import re
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import delim_parser, TypeValidator, \
    InputValidator, EnumStringParameter, TriggerParameter, CommaDelimitedStringListParameter, \
    CommaDelimitedNumberListParameter, BooleanStringParameter
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()

DIRECTIVES = [
        'ADD',
        'ARG',
        'COPY',
        'CMD',
        'ENTRYPOINT',
        'ENV',
        'EXPOSE',
        'FROM',
        'HEALTHCHECK',
        'LABEL',
        'MAINTAINER',
        'ONBUILD',
        'USER',
        'RUN',
        'SHELL',
        'STOPSIGNAL',
        'VOLUME',
        'WORKDIR'
]

CONDITIONS = [
    '=',
    '!=',
    'exists',
    'not_exists',
    'like',
    'not_like',
    'in',
    'not_in'
]


class DockerfileModeCheckedBaseTrigger(BaseTrigger):
    """
    Base class for any trigger that hard-codes selection of dockerfile mode
    """

    __actual_dockerfile_only__ = False

    def evaluate(self, image_obj, context):
        if not hasattr(context, 'data') or not context.data.get('prepared_dockerfile'):
            return
        elif self.__actual_dockerfile_only__ and (image_obj.dockerfile_mode is None or image_obj.dockerfile_mode.lower() != 'actual'):
            return
        else:
            return self._evaluate(image_obj, context)

    def _evaluate(self, image_obj, context):
        raise NotImplementedError()


class ParameterizedDockerfileModeBaseTrigger(BaseTrigger):
    """
    Base class for any trigger that lets the user decide if it applies to only actual dockerfiles or not
    """

    actual_dockerfile_only = BooleanStringParameter('actual_dockerfile_only', example_str='true', description='Only evaluate against a user-provided dockerfile, skip evaluation on inferred/guessed dockerfiles. Default is False.', is_required=False)

    def evaluate(self, image_obj, context):
        if not hasattr(context, 'data') or not context.data.get('prepared_dockerfile'):
            return
        elif self.actual_dockerfile_only.value() and (image_obj.dockerfile_mode is None or image_obj.dockerfile_mode.lower() != 'actual'):
            return
        else:
            return self._evaluate(image_obj, context)

    def _evaluate(self, image_obj, context):
        raise NotImplementedError()


class EffectiveUserTrigger(DockerfileModeCheckedBaseTrigger):
    __trigger_name__ = 'effective_user'
    __description__ = 'Checks if the effective user matches the provided user names and fires based on the allowed parameter. If allowed=true, the rule behaves as a whitelist, otherwise acts as a blacklist.'

    user = CommaDelimitedStringListParameter(name='users', example_str='root,docker', description='User names to check against as the effective user (last user entry) in the images history.', is_required=True, validator=TypeValidator('string'), sort_order=1)
    allowed_type = EnumStringParameter(name='type', enum_values=['whitelist', 'blacklist'], description='How to treat the provided user names.', is_required=True, sort_order=2)

    _sanitize_regex = '\s*USER\s+\[?([^\]]+)\]?\s*'

    def _evaluate(self, image_obj, context):
        rule_users = self.user.value()
        is_allowed = self.allowed_type.value().lower() == 'whitelist'

        user_lines = context.data.get('prepared_dockerfile').get('USER', [])

        # If not overt, make it so
        if not user_lines:
            user_lines = ['USER root']

        user = user_lines[-1].strip()  # The last USER line is the determining entry
        match = re.search(self._sanitize_regex, user)
        if match and match.groups():
            user = match.groups()[0]
        else:
            log.warn('Found USER line in dockerfile that does not match expected regex: {}, Line: {}'.format(self._sanitize_regex, user))
            return

        if is_allowed and user not in rule_users:
            self._fire(msg='User {} found as effective user, which is not on the allowed list'.format(user))
        elif not is_allowed and user in rule_users:
            self._fire(msg='User {} found as effective user, which is explicity not allowed list'.format(user))


class InstructionCheckTrigger(ParameterizedDockerfileModeBaseTrigger):
    __trigger_name__ = 'instruction'
    __description__ = 'Triggers if any directives in the list are found to match the described condition in the dockerfile.'

    instruction = EnumStringParameter(name='instruction', example_str='from', description='The Dockerfile instruction to check.', enum_values=DIRECTIVES, is_required=True, related_to='check', sort_order=1)
    operator = EnumStringParameter(name='check', example_str='=', description='The type of check to perform.', enum_values=CONDITIONS, is_required=True, related_to='directive, check_value', sort_order=2)
    compare_to = TriggerParameter(name='value', example_str='scratch', description='The value to check the dockerfile instruction against.', is_required=False, related_to='directive, check', validator=TypeValidator("string"), sort_order=3)

    _operations_requiring_check_val = [
        '=', '!=', 'like', 'not_like', 'in', 'not_in'
    ]

    ops = {
        '=': lambda x, y: x == y,
        '!=': lambda x, y: x != y,
        'exists': lambda x, y: True,
        'not_exists': lambda x, y: False,
        'like': lambda x, y: bool(re.match(y, x)),
        'not_like': lambda x, y: not bool(re.match(y, x)),
        'in': lambda x, y: x in [z.strip() for z in y.split(',')],
        'not_in': lambda x, y: x not in [z.strip() for z in y.split(',')]
    }

    def _evaluate(self, image_obj, context):
        directive = self.instruction.value() # Note: change from multiple values to a single value
        condition = self.operator.value(default_if_none='')
        check_value = self.compare_to.value()
        operation = self.ops.get(condition)

        if condition in self._operations_requiring_check_val and check_value is None:
            return

        if not condition or not directive:
            return

        df = context.data.get('prepared_dockerfile')

        for directive_name, lines in [x for x in list(df.items()) if x[0] == directive]:
            for l in lines:
                l = l[len(directive_name):].strip()
                if operation(l, check_value):
                    self._fire(msg="Dockerfile directive '{}' check '{}' matched against '{}' for line '{}'".format(directive_name, condition, check_value if check_value else '', l))

        upper_keys = set([x.upper() for x in list(df.keys())])
        if condition == 'not_exists' and directive not in upper_keys:
            self._fire(msg="Dockerfile directive '{}' not found, matching condition '{}' check".format(directive, condition))


class ExposedPortsTrigger(ParameterizedDockerfileModeBaseTrigger):
    __trigger_name__ = 'exposed_ports'
    __description__ = 'Evaluates the set of ports exposed. Allows configuring whitelist or blacklist behavior. If type=whitelist, then any ports found exposed that are not in the list will cause the trigger to fire. If type=blacklist, then any ports exposed that are in the list will cause the trigger to fire.'

    ports = CommaDelimitedNumberListParameter(name='ports', example_str='80,8080,8088', description='List of port numbers.', is_required=True, sort_order=1)
    allowed_type = EnumStringParameter(name='type', example_str='blacklist', enum_values=['whitelist', 'blacklist'], description='Whether to use port list as a whitelist or blacklist.', is_required=True, sort_order=2)

    def _evaluate(self, image_obj, context):
        if self.allowed_type.value().lower() == 'whitelist':
            whitelisted_ports = [str(x) for x in self.ports.value(default_if_none=[])]
            blacklisted_ports = []
        elif self.allowed_type.value().lower() == 'blacklist':
            whitelisted_ports = []
            blacklisted_ports = [str(x) for x in self.ports.value(default_if_none=[])]
        else:
            raise ValueError('Invalid value for "type" parameter: {}'.format(self.allowed_type.value()))

        expose_lines = context.data.get('prepared_dockerfile', {}).get('EXPOSE', [])

        for line in expose_lines:
            matchstr = None
            line = line.strip()
            if re.match("^\s*(EXPOSE|" + 'EXPOSE'.lower() + ")\s+(.*)", line):
                matchstr = re.match("^\s*(EXPOSE|" + 'EXPOSE'.lower() + ")\s+(.*)", line).group(2)

            if matchstr:
                iexpose = matchstr.split()
                if blacklisted_ports:
                    if 0 in blacklisted_ports and len(iexpose) > 0:
                        self._fire(msg="Dockerfile exposes network ports but policy sets DENIEDPORTS=0: " + str(iexpose))
                    else:
                        for p in blacklisted_ports:
                            if p in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + ") which is in policy file DENIEDPORTS list")
                            elif p + '/tcp' in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + "/tcp) which is in policy file DENIEDPORTS list")
                            elif p + '/udp' in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + "/udp) which is in policy file DENIEDPORTS list")

                if whitelisted_ports:
                    if 0 in whitelisted_ports and len(iexpose) > 0:
                        self._fire(msg="Dockerfile exposes network ports but policy sets ALLOWEDPORTS=0: " + str(iexpose))
                    else:
                        for p in whitelisted_ports:
                            done = False
                            while not done:
                                try:
                                    iexpose.remove(str(p))
                                    done = False
                                except:
                                    done = True

                                try:
                                    iexpose.remove(str(p) + '/tcp')
                                    done = False
                                except:
                                    done = True

                                try:
                                    iexpose.remove(str(p) + '/udp')
                                    done = False
                                except:
                                    done = True

                        for ip in iexpose:
                            self._fire(msg="Dockerfile exposes port (" + ip + ") which is not in policy file ALLOWEDPORTS list")
        return


class NoDockerfile(BaseTrigger):
    __trigger_name__ = 'no_dockerfile_provided'
    __description__ = 'Triggers if anchore analysis was performed without supplying the actual image Dockerfile.'
    __msg__ = 'Image was not analyzed with an actual Dockerfile'

    def evaluate(self, image_obj, context):
        """
        Evaluate using the initialized values for this object:        
        """
        if image_obj.dockerfile_mode is None or image_obj.dockerfile_mode.lower() != 'actual':
            self._fire()


class DockerfileGate(Gate):
    __gate_name__ = 'dockerfile'
    __description__ = 'Checks against the content of a dockerfile if provided, or a guessed dockerfile based on docker layer history if the dockerfile is not provided.'
    __triggers__ = [
        InstructionCheckTrigger,
        EffectiveUserTrigger,
        ExposedPortsTrigger,
        NoDockerfile
    ]

    def prepare_context(self, image_obj, context):
        """
        Pre-processes the image's dockerfile.
        Leaves the context with a dictionary of dockerfile lines by directive.
        e.g. 
        context.data['dockerfile']['RUN'] = ['RUN apt-get update', 'RUN blah']
        context.data['dockerfile']['VOLUME'] = ['VOLUME /tmp', 'VOLUME /var/log']
        
        :rtype: object
        :return: updated context
        """

        # Optimization by single-pass parsing the docker file instead of one per trigger eval.
        # unknown/known is up to each trigger

        if image_obj.dockerfile_mode is None or image_obj.dockerfile_mode.lower() == "unknown":
            return

        context.data['prepared_dockerfile'] = {}

        if image_obj.dockerfile_contents:
            linebuf = ""
            for line in image_obj.dockerfile_contents.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    patt = re.match(".*\\\$", line)
                    if patt:
                        line = re.sub("\\\$", "", line)
                        linebuf = linebuf + line
                    else:
                        linebuf = linebuf + line
                        if linebuf:
                            tokens = linebuf.split(' ', 1)
                            if tokens:
                                directive = tokens[0]
                            else:
                                directive = ''

                            directive = directive.upper()
                            if directive not in context.data['prepared_dockerfile']:
                                context.data['prepared_dockerfile'][directive] = []
                            context.data['prepared_dockerfile'][directive].append(linebuf)
                            linebuf = ""
                else:
                    continue
                    # Skip comment lines in the dockerfile

        return context
