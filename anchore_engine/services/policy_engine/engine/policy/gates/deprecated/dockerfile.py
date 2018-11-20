import re
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate, LifecycleStates
from anchore_engine.services.policy_engine.engine.policy.params import delim_parser, TypeValidator, \
    InputValidator, EnumStringParameter, TriggerParameter, CommaDelimitedStringListParameter, \
    CommaDelimitedNumberListParameter, EnumCommaDelimStringListParameter
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


class EffectiveUserTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'effectiveuser'
    __description__ = 'Triggers if the effective user for the container is either root when not allowed or is not in a whitelist'

    allowed_users = CommaDelimitedStringListParameter(name='allowed', example_str='nginx,postgres', description='List of user names allowed to be the effective user (last user entry) in the images history', is_required=False)
    denied_users = CommaDelimitedStringListParameter(name='denied', example_str='root', description='List of user names forbidden from being the effective user for the image in the image history', is_required=False)

    _sanitize_regex = '\s*USER\s+\[?([^\]]+)\]?\s*'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return # Prep step blocked this eval due to condition on the dockerfile, so skip

        allowed_users = self.allowed_users.value(default_if_none=[])
        denied_users = self.denied_users.value(default_if_none=[])

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

        if allowed_users and user not in allowed_users:
            self._fire(msg='User {} found as effective user, which is not on the allowed list'.format(user))
        if denied_users and user in denied_users:
            self._fire(msg='User {} found as effective user, which is on the denied list'.format(user))


class DirectiveCheckTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'directivecheck'
    __description__ = 'Triggers if any directives in the list are found to match the described condition in the dockerfile'

    directive = EnumStringParameter(name='directives', example_str='COPY', description='The Dockerfile instruction to check', enum_values=DIRECTIVES, is_required=True, related_to='check', sort_order=1)
    check = EnumStringParameter(name='check', example_str='=', description='The type of check to perform', enum_values=CONDITIONS, is_required=True, related_to='directive, check_value', sort_order=2)
    check_value = TriggerParameter(name='check_value', example_str='./app /app', description='The value to check the dockerfile instruction against', is_required=False, related_to='directive, check', validator=TypeValidator("string"), sort_order=3)

    _conditions_requiring_check_val = [
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

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return # Prep step blocked this eval due to condition on the dockerfile, so skip

        directive = self.directive.value() # Note: change from multiple values to a single value
        condition = self.check.value(default_if_none='')
        check_value = self.check_value.value(default_if_none=[])
        operation = self.ops.get(condition)

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


class ExposeTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'expose'

    allowed_ports = CommaDelimitedNumberListParameter(name='allowedports', example_str='80,8088', description='Comma delimited list of port numbers to allow (as a string)', is_required=False)
    denied_ports = CommaDelimitedNumberListParameter(name='deniedports', example_str='22,53', description='Comma delimited list of port numbers to deny (as a string)', is_required=False)

    __description__ = 'triggers if Dockerfile is EXPOSEing ports that are not in ALLOWEDPORTS, or are in DENIEDPORTS'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        allowed_ports = [str(x) for x in self.allowed_ports.value(default_if_none=[])]
        denied_ports = [str(x) for x in self.denied_ports.value(default_if_none=[])]

        expose_lines = context.data.get('prepared_dockerfile', {}).get('EXPOSE', [])
        for line in expose_lines:
            matchstr = None
            line = line.strip()
            if re.match("^\s*(EXPOSE|" + 'EXPOSE'.lower() + ")\s+(.*)", line):
                matchstr = re.match("^\s*(EXPOSE|" + 'EXPOSE'.lower() + ")\s+(.*)", line).group(2)

            if matchstr:
                iexpose = matchstr.split()
                if denied_ports:
                    if 'ALL' in denied_ports and len(iexpose) > 0:
                        self._fire(msg="Dockerfile exposes network ports but policy sets DENIEDPORTS=ALL: " + str(iexpose))
                    else:
                        for p in denied_ports:
                            if p in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + ") which is in policy file DENIEDPORTS list")
                            elif p + '/tcp' in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + "/tcp) which is in policy file DENIEDPORTS list")
                            elif p + '/udp' in iexpose:
                                self._fire(msg="Dockerfile exposes port (" + p + "/udp) which is in policy file DENIEDPORTS list")

                if allowed_ports:
                    if 'NONE' in allowed_ports and len(iexpose) > 0:
                        self._fire(msg="Dockerfile exposes network ports but policy sets ALLOWEDPORTS=NONE: " + str(iexpose))
                    else:
                        for p in allowed_ports:
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

                        # Replaecable by:
                        # for port in filter(lambda x: x.split('/')[0] not in allowed_ports, iexpose):
                        #   self._fire(...)
        return


class NoFromTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'nofrom'
    __params__ = None
    __description__ = 'triggers if there is no FROM line specified in the Dockerfile'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        from_lines = context.data['prepared_dockerfile'].get('FROM')
        if not from_lines:
            self._fire(msg="No 'FROM' directive in Dockerfile")
            return


class FromScratch(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'fromscratch'
    __description__ = 'triggers the FROM line specified "scratch" as the parent'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        from_lines = context.data['prepared_dockerfile'].get('FROM', [])
        for line in from_lines:
            fromstr = None
            if re.match("^\s*(FROM|" + 'FROM'.lower() + ")\s+(.*)", line):
                fromstr = re.match("^\s*(FROM|" + 'FROM'.lower() + ")\s+(.*)", line).group(2)

            if fromstr == 'SCRATCH' or fromstr.lower() == 'scratch':
                self._fire(msg="'FROM' container is 'scratch' - (" + str(fromstr) + ")")


class NoTag(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'notag'
    __description__ = 'triggers if the FROM container specifies a repo but no explicit, non-latest tag'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        from_lines = context.data['prepared_dockerfile'].get('FROM', [])
        for line in from_lines:
            fromstr = None
            if re.match("^\s*(FROM|" + 'FROM'.lower() + ")\s+(.*)", line):
                fromstr = re.match("^\s*(FROM|" + 'FROM'.lower() + ")\s+(.*)", line).group(2)

            if fromstr:
                if re.match("(\S+):(\S+)", fromstr):
                    repo, tag = re.match("(\S+):(\S+)", fromstr).group(1, 2)
                    if tag == 'latest':
                        self._fire(msg="container does not specify a non-latest container tag - (" + str(
                            fromstr) + ")")
                else:
                    self._fire(msg="container does not specify a non-latest container tag - (" + str(fromstr) + ")")


class Sudo(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'sudo'
    __description__ = 'triggers if the Dockerfile contains operations running with sudo'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        if image_obj.dockerfile_contents:
            for line in image_obj.dockerfile_contents.splitlines():
                line = line.strip()
                if re.match(".*sudo.*", line):
                    self._fire(msg="Dockerfile contains a 'sudo' command: " + str(line))


class VolumePresent(BaseTrigger):
    __trigger_name__ = 'volumepresent'
    __description__ = 'triggers if the Dockerfile contains a VOLUME line'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        for line in context.data['prepared_dockerfile'].get('VOLUME', []):
            self._fire(msg='Dockerfile contains a VOLUME line: ' + str(line))

class NoHealthCheck(BaseTrigger):
    __trigger_name__ = 'nohealthcheck'
    __description__ = 'triggers if the Dockerfile does not contain any HEALTHCHECK instructions'
    __msg__ = 'Dockerfile does not contain any HEALTHCHECK instructions'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        if not context.data['prepared_dockerfile'].get('HEALTHCHECK'):
            self._fire()


class NoDockerfile(BaseTrigger):
    __trigger_name__ = 'nodockerfile'
    __description__ = 'triggers if anchore analysis was performed without supplying a real Dockerfile'
    __msg__ = 'Image was not analyzed with an actual Dockerfile'

    def evaluate(self, image_obj, context):
        """
        Evaluate using the initialized values for this object:        
        """
        if image_obj.dockerfile_mode != 'Actual':
            self._fire()


class DockerfileGate(Gate):
    __gate_name__ = 'dockerfilecheck'
    __description__ = 'Check Dockerfile Instructions'
    __lifecycle_state__ = LifecycleStates.deprecated
    __superceded_by__ = 'dockerfile'
    __triggers__ = [
        DirectiveCheckTrigger,
        EffectiveUserTrigger,
        ExposeTrigger,
        NoFromTrigger,
        FromScratch,
        NoTag,
        Sudo,
        VolumePresent,
        NoHealthCheck,
        NoDockerfile
    ]

    def prepare_context(self, image_obj, context):
        """
        Pre-processes the image's dockerfile.
        Leaves the context with a dictionary of dockerfile lines by directive.
        e.g. 
        context.data['dockerfile']['RUN'] = ['RUN apt-get update', 'RUN blah']
        context.data['dockerfile']['VOLUME'] = ['VOLUME /tmp', 'VOLUMN /var/log']
        
        :rtype:
        :return: updated context
        """

        # Optimization by single-pass parsing the docker file instead of one per trigger eval.
        # unknown/known is up to each trigger

        if image_obj.dockerfile_mode == "Unknown":
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
