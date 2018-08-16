import re
import stat
import base64
from anchore_engine.utils import ensure_str, ensure_bytes
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import PipeDelimitedStringListParameter, TriggerParameter, TypeValidator
from anchore_engine.db import AnalysisArtifact
log = get_logger()


class ContentMatchTrigger(BaseTrigger):
    __trigger_name__ = 'content_regex_match'
    __description__ = 'Triggers for each file where the content search analyzer has found a match using configured regexes in the analyzer_config.yaml "content_search" section. If the parameter is set, the trigger will only fire for files that matched the named regex. Refer to your analyzer_config.yaml for the regex values.'

    regex_name = TriggerParameter(validator=TypeValidator('string'), name='regex_name', example_str='.*password.*', description='Regex string that also appears in the FILECHECK_CONTENTMATCH analyzer parameter in analyzer configuration, to limit the check to. If set, will only fire trigger when the specific named regex was found in a file.',
                                  is_required=False)

    def evaluate(self, image_obj, context):
        match_filter = self.regex_name.value()

        if match_filter:
            match_decoded = ensure_str(base64.b64encode(ensure_bytes(match_filter)))
        else:
            return

        for thefile, regexps in list(context.data.get('content_regexp', {}).items()):
            thefile = ensure_str(thefile)
            if not regexps:
                continue
            for regexp in regexps.keys():
                decoded_regexp = ensure_str(base64.b64decode(ensure_bytes(regexp)))
                try:
                    regexp_name, theregexp = decoded_regexp.split("=", 1)
                except:
                    regexp_name = None
                    theregexp = decoded_regexp

                if not match_filter:
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))
                elif regexp == match_filter or theregexp == match_decoded:
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))
                elif regexp_name and regexp_name == match_decoded:
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, decoded_regexp))


class FilenameMatchTrigger(BaseTrigger):
    __trigger_name__ = 'name_match'
    __description__ = 'Triggers if a file exists in the container that has a filename that matches the provided regex. This does have a performance impact on policy evaluation.'

    regex = TriggerParameter(validator=TypeValidator('string'), name='regex', example_str='.*\.pem', description='Regex to apply to file names for match.', is_required=True)

    def evaluate(self, image_obj, context):
        # decode the param regexes from b64
        regex_param = self.regex.value()

        files = []
        if hasattr(context, 'data'):
            files = context.data.get('filenames')

        for thefile in files:
            thefile = ensure_str(thefile)
            if re.match(regex_param, thefile):
                self._fire(msg='Application of regex matched file found in container: file={} regexp={}'.format(thefile, regex_param))


class SuidCheckTrigger(BaseTrigger):
    __trigger_name__ = 'suid_or_guid_set'
    __description__ = 'Fires for each file found to have suid or sgid bit set.'

    def evaluate(self, image_obj, context):
        if not image_obj.fs:
            return

        files = image_obj.fs.files
        if not files:
            return

        found = [x for x in list(files.items()) if (int(x[1].get('mode', 0)) & (stat.S_ISUID | stat.S_ISGID))]
        for path, entry in found:
            self._fire(msg='SUID or SGID found set on file {}. Mode: {}'.format(path, oct(entry.get('mode'))))


class FileCheckGate(Gate):
    __gate_name__ = 'files'
    __description__ = 'Checks against files in the analyzed image including file content, file names, and filesystem attributes.'
    __triggers__ = [
        ContentMatchTrigger,
        FilenameMatchTrigger,
        SuidCheckTrigger
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

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'content_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base').all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data['content_regexp'] = matches

        return context
