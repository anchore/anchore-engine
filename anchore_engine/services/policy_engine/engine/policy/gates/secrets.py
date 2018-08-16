import re
import base64
from anchore_engine.utils import ensure_bytes, ensure_str
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import TypeValidator, TriggerParameter
from anchore_engine.db import AnalysisArtifact
log = get_logger()


default_included_regex_names = ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PRIV_KEY", "DOCKER_AUTH", "API_KEY"]


class SecretContentChecksTrigger(BaseTrigger):
    __trigger_name__ = 'content_regex_checks'
    __description__ = 'Triggers if the content search analyzer has found any matches with the configured and named regexes. Matches are filtered by the content_regex_name and filename_regex if they are set. The content_regex_name shoud be a value from the "secret_search" section of the analyzer_config.yaml.'

    secret_contentregexp = TriggerParameter(name='content_regex_name', validator=TypeValidator('string'), example_str=default_included_regex_names[0], description='Name of content regexps configured in the analyzer that should trigger if found in the image, instead of triggering for any match. Names available by default are: {}.'.format(default_included_regex_names))
    name_regexps = TriggerParameter(name='filename_regex', validator=TypeValidator('string'), example_str='/etc/.*', description='Regexp to filter the content matched files by.')

    def evaluate(self, image_obj, context):
        match_filter = self.secret_contentregexp.value(default_if_none=[])
        name_re = re.compile(self.name_regexps.value()) if self.name_regexps.value() else None

        if match_filter:
            matches = [base64.b64encode(ensure_bytes(x)) for x in match_filter]
            matches_decoded = match_filter
        else:
            matches = []
            matches_decoded = []

        for thefile, regexps in list(context.data.get('secret_content_regexp', {}).items()):
            thefile = ensure_str(thefile)

            if not regexps:
                continue

            if regexps and (not name_re or name_re.match(thefile)):
                for regexp in list(regexps.keys()):
                    decoded_regexp = ensure_str(base64.b64decode(ensure_bytes(regexp)))

                    try:
                        regexp_name, theregexp = decoded_regexp.split("=", 1)
                    except:
                        regexp_name = None
                        theregexp = decoded_regexp

                    if not matches:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))
                    elif regexp in matches or theregexp in matches_decoded:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))
                    elif regexp_name and regexp_name in matches_decoded:
                        self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))


class SecretCheckGate(Gate):
    __gate_name__ = 'secret_scans'
    __description__ = 'Checks for secrets found in the image using configured regexes found in the "secret_search" section of analyzer_config.yaml.'
    __triggers__ = [
        SecretContentChecksTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        prepare the context by extracting the file name list once and placing it in the eval context to avoid repeated
        loads from the db. this is an optimization and could removed.

        :rtype:
        :param image_obj:
        :param context:
        :return:
        """

        if image_obj.fs:
            extracted_files_json = image_obj.fs.files

            if extracted_files_json:
                context.data['filenames'] = list(extracted_files_json.keys())

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'secret_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base').all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data['secret_content_regexp'] = matches

        return context
