import re
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.utils import PipeDelimitedStringListValidator
from anchore_engine.db import AnalysisArtifact
log = get_logger()


class SecretContentMatchTrigger(BaseTrigger):
    __trigger_name__ = 'CONTENTMATCH'
    __description__ = 'Triggers if the content search analyzer has found any matches.  If the parameter is set, then will only trigger against found matches that are also in the SECRETCHECK_CONTENTREGEXP parameter list.  If the parameter is absent or blank, then the trigger will fire if the analyzer found any matches.'
    __params__ = {
        'SECRETCHECK_CONTENTREGEXP': PipeDelimitedStringListValidator()
    }

    def evaluate(self, image_obj, context):
        match_filter = self.eval_params.get(self.__params__.keys()[0])

        if match_filter:
            matches = [x.encode('base64') for x in match_filter.split('|')]
            matches_decoded = match_filter.split('|')
        else:
            matches = []
            matches_decoded = []

        for thefile, regexps in context.data.get('secret_content_regexp', {}).items():
            thefile = thefile.encode('ascii', errors='replace')
            if not regexps:
                continue
            for regexp in regexps.keys():
                try:
                    regexp_name, theregexp = regexp.decode('base64').split("=", 1)
                except:
                    regexp_name = None
                    theregexp = regexp.decode('base64')

                if not matches:
                    self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                elif regexp in matches or theregexp in matches_decoded:
                    self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                elif regexp_name and regexp_name in matches_decoded:
                    self._fire(msg='Secret search analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))


class SecretFilenameMatchTrigger(BaseTrigger):
    __trigger_name__ = 'FILENAMEMATCH'
    __description__ = 'Triggers if a file exists in the container that matches with any of the regular expressions given as SECRETCHECK_NAMEREGEXP parameters.'
    __params__ = {
        'SECRETCHECK_NAMEREGEXP': PipeDelimitedStringListValidator()
    }

    def evaluate(self, image_obj, context):
        # decode the param regexes from b64
        fname_regexps = []
        regex_param = self.eval_params.get(self.__params__.keys()[0])
        if regex_param:
            fname_regexps = regex_param.split('|')

        if not fname_regexps:
            # Short circuit
            return

        if context.data.get('filenames'):
            files = context.data.get('filenames')
        else:
            files = image_obj.fs.files().keys()  # returns a map of path -> entry

        for thefile in files:
            thefile = thefile.encode('ascii', errors='replace')
            for regexp in fname_regexps:
                if re.match(regexp, thefile):
                    self._fire(msg='Application of regexp matched file found in container: file={} regexp={}'.format(thefile, regexp))


class SecretCheckGate(Gate):
    __gate_name__ = 'SECRETCHECK'
    __triggers__ = [
        SecretContentMatchTrigger,
        SecretFilenameMatchTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        prepare the context by extracting the file name list once and placing it in the eval context to avoid repeated
        loads from the db. this is an optimization and could removed.

        :param image_obj:
        :param context:
        :return:
        """

        if image_obj.fs:
            extracted_files_json = image_obj.fs.files

            if extracted_files_json:
                context.data['filenames'] = extracted_files_json.keys()

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'secret_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base').all()
        log.info("HELLOHELLO: " + str(content_matches))
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data['secret_content_regexp'] = matches

        log.info("HELLO: " + str(context.data))

        return context
