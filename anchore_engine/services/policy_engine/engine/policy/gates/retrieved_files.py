import re

from anchore_engine.db import AnalysisArtifact
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    EnumStringParameter,
    SimpleStringParameter,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_str


class RetrievedFileMixin(object):
    # Common parameter to specify the file to check
    file_path = SimpleStringParameter(
        name="path",
        example_str="/etc/httpd.conf",
        description="The path of the file to verify has been retrieved during analysis",
        is_required=True,
        sort_order=1,
    )

    def get_file(self, context):
        """
        Process a blacklist against pentries

        :param blacklist_items: list of strings to check for in pentry locations
        :param pentry_index: item index in the pentry to check against, -1 means user-name, and None means entire entry
        :param pentries_dict: {'username': <array form of a pentry minus usename> }
        :return: list of match tuples where each tuple is (<matched candidate>, <entire matching pentry>)
        """
        path = self.file_path.value()

        if context is None or context.data is None:
            return False

        for f in context.data.get("retrieved_files"):
            if f.artifact_key == path:
                return f

        return None


class FileNotStoredTrigger(BaseTrigger, RetrievedFileMixin):
    __trigger_name__ = "content_not_available"
    __description__ = (
        "Triggers if the specified file is not present/stored in the evaluated image."
    )
    __msg__ = "Cannot locate file in the image analysis"

    def evaluate(self, image_obj, context):
        if not context.data.get("retrieved_files"):
            self._fire()

        if self.get_file(context) is None:
            self._fire()


class FileContentRegexMatchTrigger(BaseTrigger, RetrievedFileMixin):
    __trigger_name__ = "content_regex"
    __description__ = "Evaluation of regex on retrieved file content"

    regex = SimpleStringParameter(
        name="regex",
        example_str=".*SSlEnabled.*",
        description="The regex to evaluate against the content of the file",
        is_required=True,
    )
    check = EnumStringParameter(
        name="check",
        example_str="match",
        enum_values=["match", "no_match"],
        description="The type of check to perform with the regex",
        is_required=True,
    )

    def _construct_match_id(self):
        return "{id}+file://{path}".format(id=self.rule_id, path=self.file_path.value())

    def evaluate(self, image_obj, context):
        if not context.data.get("retrieved_files"):
            return

        re_value = self.regex.value()
        check_type = self.check.value()
        path = self.file_path.value()
        file = self.get_file(context)
        compiled_re = re.compile(re_value)

        if (
            re_value is None
            or check_type is None
            or compiled_re is None
            or file is None
            or file.binary_value is None
        ):
            return

        # Decode b64
        try:
            file_content = ensure_str(file.binary_value)
        except Exception as e:
            logger.exception(
                "Could not decode/process file content for {} in image {}/{} to do regex check".format(
                    path, image_obj.user_id, image_obj.id
                )
            )
            raise Exception(
                "Cannot execute regex check due to error processing file content"
            )

        if file_content is None:
            return

        match_found = False
        for line in file_content.split():
            match_found = match_found or (compiled_re.match(line) is not None)

        if match_found == (check_type == "match"):
            self._fire(
                instance_id=self._construct_match_id(),
                msg="Content regex '{}' check '{}' found in retrieved file '{}'".format(
                    re_value, check_type, path
                ),
            )


class RetrievedFileChecksGate(Gate):
    __gate_name__ = "retrieved_files"
    __description__ = "Checks against content and/or presence of files retrieved at analysis time from an image"
    __triggers__ = [
        FileNotStoredTrigger,
        FileContentRegexMatchTrigger,
    ]

    def prepare_context(self, image_obj, context):
        """
        prepare the context by extracting the /etc/passwd content for the image from the analysis artifacts list if it is found.
        loads from the db.

        This is an optimization and could removed, but if removed the triggers should be updated to do the queries directly.

        :rtype:
        :param image_obj:
        :param context:
        :return:
        """

        retrieved_file_contents = image_obj.analysis_artifacts.filter(
            AnalysisArtifact.analyzer_id == "retrieve_files",
            AnalysisArtifact.analyzer_artifact == "file_content.all",
            AnalysisArtifact.analyzer_type == "base",
        ).all()
        context.data["retrieved_files"] = retrieved_file_contents
        return context
