import re
import stat
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import PipeDelimitedStringListParameter
from anchore_engine.db import AnalysisArtifact
log = get_logger()


class ContentMatchTrigger(BaseTrigger):
    __trigger_name__ = 'contentmatch'
    __description__ = 'Triggers if the content search analyzer has found any matches.  If the parameter is set, then will only trigger against found matches that are also in the FILECHECK_CONTENTMATCH parameter list.  If the parameter is absent or blank, then the trigger will fire if the analyzer found any matches.'

    contentregex_names = PipeDelimitedStringListParameter(name='filecheck_contentregexp', description='Pipe delimited list of named regexes from the FILECHECK_CONTENTMATCH parameter list for the analyzers')

    def evaluate(self, image_obj, context):
        #match_filter = self.eval_params.get(self.__params__.keys()[0])
        match_filter = self.contentregex_names.value()

        if match_filter:
            matches = [x.encode('base64') for x in match_filter]
            matches_decoded = match_filter
        else:
            matches = []
            matches_decoded = []

        for thefile, regexps in context.data.get('content_regexp', {}).items():
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
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                elif regexp in matches or theregexp in matches_decoded:
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))
                elif regexp_name and regexp_name in matches_decoded:
                    self._fire(msg='File content analyzer found regexp match in container: file={} regexp={}'.format(thefile, regexp.decode('base64')))


class FilenameMatchTrigger(BaseTrigger):
    __trigger_name__ = 'filenamematch'
    __description__ = 'Triggers if a file exists in the container that matches with any of the regular expressions given as FILECHECK_NAMEREGEXP parameters.'

    regex_names = PipeDelimitedStringListParameter(name='filecheck_nameregexp', description='Pipe-delimited list of names of regexes from the FILECHECK_NAMEREGEXP paramter in the analyzer configuration')

    def evaluate(self, image_obj, context):
        # decode the param regexes from b64
        fname_regexps = []
        #regex_param = self.eval_params.get(self.__params__.keys()[0])
        regex_param = self.regex_names.value()

        if regex_param:
            fname_regexps = regex_param

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


class SuidCheckTrigger(BaseTrigger):
    __trigger_name__ = 'suidsgidcheck'
    __description__ = 'Fires for each file found to have suid or sgid set'

    def evaluate(self, image_obj, context):
        if not image_obj.fs:
            return

        files = image_obj.fs.files
        if not files:
            return

        found = filter(lambda x: (int(x[1].get('mode', 0)) & (stat.S_ISUID | stat.S_ISGID)), files.items())
        for path, entry in found:
            self._fire(msg='SUID or SGID found set on file {}. Mode: {}'.format(path, oct(entry.get('mode'))))



class FileCheckGate(Gate):
    __gate_name__ = 'filecheck'
    __description__ = 'Image File Checks'
    __triggers__ = [
        ContentMatchTrigger,
        FilenameMatchTrigger,
        SuidCheckTrigger
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

        content_matches = image_obj.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'content_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base').all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data['content_regexp'] = matches

        return context
