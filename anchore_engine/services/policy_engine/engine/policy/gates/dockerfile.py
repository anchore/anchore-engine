import re
import logging
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.utils import RegexParamValidator, CommaDelimitedNumberListValidator, NameVersionListValidator, \
    CommaDelimitedStringListValidator, delim_parser
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class ExposeTrigger(BaseTrigger):
    __trigger_name__ = 'EXPOSE'

    __params__ = {
        'ALLOWEDPORTS': CommaDelimitedNumberListValidator(),
        'DENIEDPORTS': CommaDelimitedNumberListValidator()
    }
    __description__ = 'triggers if Dockerfile is EXPOSEing ports that are not in ALLOWEDPORTS, or are in DENIEDPORTS'


    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        allowed_ports = delim_parser(self.eval_params.get('ALLOWEDPORTS', ''))
        denied_ports = delim_parser(self.eval_params.get('DENIEDPORTS', ''))

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
                                    iexpose.remove(p)
                                    done = False
                                except:
                                    done = True

                                try:
                                    iexpose.remove(p + '/tcp')
                                    done = False
                                except:
                                    done = True

                                try:
                                    iexpose.remove(p + '/udp')
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
    __trigger_name__ = 'NOFROM'
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
    __trigger_name__ = 'FROMSCRATCH'
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
    __trigger_name__ = 'NOTAG'
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
    __trigger_name__ = 'SUDO'
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
    __trigger_name__ = 'VOLUMEPRESENT'
    __description__ = 'triggers if the Dockerfile contains a VOLUME line'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        for line in context.data['prepared_dockerfile'].get('VOLUME', []):
            self._fire(msg='Dockerfile contains a VOLUME line: ' + str(line))

class NoHealthCheck(BaseTrigger):
    __trigger_name__ = 'NOHEALTHCHECK'
    __description__ = 'triggers if the Dockerfile does not contain any HEALTHCHECK instructions'
    __msg__ = 'Dockerfile does not contain any HEALTHCHECK instructions'

    def evaluate(self, image_obj, context):
        if not context.data.get('prepared_dockerfile'):
            return  # Prep step blocked this due to condition on the dockerfile, so skip

        if not context.data['prepared_dockerfile'].get('HEALTHCHECK'):
            self._fire()


class NoDockerfile(BaseTrigger):
    __trigger_name__ = 'NODOCKERFILE'
    __description__ = 'triggers if anchore analysis was performed without supplying a real Dockerfile'
    __msg__ = 'Image was not analyzed with an actual Dockerfile'

    def evaluate(self, image_obj, context):
        """
        Evaluate using the initialized values for this object:        
        """
        if image_obj.dockerfile_mode != 'Actual':
            self._fire()


class DockerfileGate(Gate):
    __gate_name__ = 'DOCKERFILECHECK'

    __triggers__ = [
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
        
        :return: updated context        
        """

        # Optimization by single-pass parsing the docker file instead of one per trigger eval.
        # unknown/known is up to each trigger

        if image_obj.dockerfile_mode == "Unknown":
            return

        context.data['prepared_dockerfile'] = {}

        if image_obj.dockerfile_contents:
            for line in image_obj.dockerfile_contents.splitlines():
                line = line.strip()
                if not line.startswith('#'):
                    directive, remainder = line.split(' ', 1)
                    directive = directive.upper() # Normalize to all upper
                    if directive not in context.data['prepared_dockerfile']:
                        context.data['prepared_dockerfile'][directive] = []

                    context.data['prepared_dockerfile'][directive].append(line)
                else:
                    continue
                    # Skip comment lines in the dockerfile

        return context
