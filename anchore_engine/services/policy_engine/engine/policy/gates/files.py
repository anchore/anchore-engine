import base64
import re
import stat

from anchore_engine.db import AnalysisArtifact
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    BooleanStringParameter,
    EnumStringParameter,
    TriggerParameter,
    TypeValidator,
)
from anchore_engine.utils import ensure_bytes, ensure_str


class ContentMatchTrigger(BaseTrigger):
    __trigger_name__ = "content_regex_match"
    __description__ = 'Triggers for each file where the content search analyzer has found a match using configured regexes in the analyzer_config.yaml "content_search" section. If the parameter is set, the trigger will only fire for files that matched the named regex. Refer to your analyzer_config.yaml for the regex values.'

    regex_name = TriggerParameter(
        validator=TypeValidator("string"),
        name="regex_name",
        example_str=".*password.*",
        description="Regex string that also appears in the FILECHECK_CONTENTMATCH analyzer parameter in analyzer configuration, to limit the check to. If set, will only fire trigger when the specific named regex was found in a file.",
        is_required=False,
    )

    def evaluate(self, image_obj, context):
        match_decoded = self.regex_name.value()

        if match_decoded:
            match_encoded = ensure_str(base64.b64encode(ensure_bytes(match_decoded)))

        for thefile, regexps in list(context.data.get("content_regexp", {}).items()):
            thefile = ensure_str(thefile)
            if not regexps:
                continue
            for regexp in regexps.keys():
                found = False
                decoded_regexp = ensure_str(base64.b64decode(ensure_bytes(regexp)))
                try:
                    regexp_name, theregexp = decoded_regexp.split("=", 1)
                except:
                    regexp_name = None
                    theregexp = decoded_regexp

                if not match_decoded:
                    found = True
                elif theregexp == match_decoded or regexp == match_encoded:
                    found = True
                elif regexp_name and regexp_name == match_decoded:
                    found = True

                if found:
                    self._fire(
                        msg="File content analyzer found regexp match in container: file={} regexp={}".format(
                            thefile, decoded_regexp
                        )
                    )


class FilenameMatchTrigger(BaseTrigger):
    __trigger_name__ = "name_match"
    __description__ = "Triggers if a file exists in the container that has a filename that matches the provided regex. This does have a performance impact on policy evaluation."

    regex = TriggerParameter(
        validator=TypeValidator("string"),
        name="regex",
        example_str=r".*\.pem",
        description="Regex to apply to file names for match.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        # decode the param regexes from b64
        regex_param = self.regex.value()

        files = []
        if hasattr(context, "data"):
            files = context.data.get("filenames")

        for thefile in files:
            thefile = ensure_str(thefile)
            if re.match(regex_param, thefile):
                self._fire(
                    msg="Application of regex matched file found in container: file={} regexp={}".format(
                        thefile, regex_param
                    )
                )


class FileAttributeMatchTrigger(BaseTrigger):
    __trigger_name__ = "attribute_match"
    __description__ = "Triggers if a filename exists in the container that has attributes that match those which are provided . This check has a performance impact on policy evaluation."

    filename = TriggerParameter(
        validator=TypeValidator("string"),
        name="filename",
        example_str="/etc/passwd",
        description="Filename to check against provided checksum.",
        is_required=True,
        sort_order=1,
    )

    checksum_algo = EnumStringParameter(
        name="checksum_algorithm",
        enum_values=["sha256"],
        example_str="sha256",
        description="Checksum algorithm",
        is_required=False,
        sort_order=2,
    )
    checksum = TriggerParameter(
        validator=TypeValidator("string"),
        name="checksum",
        example_str="832cd0f75b227d13aac82b1f70b7f90191a4186c151f9db50851d209c45ede11",
        description="Checksum of file.",
        is_required=False,
        sort_order=3,
    )

    checksum_op = EnumStringParameter(
        name="checksum_match",
        enum_values=["equals", "not_equals"],
        example_str="equals",
        description="Checksum operation to perform.",
        is_required=False,
        sort_order=4,
    )

    mode = TriggerParameter(
        validator=TypeValidator("string"),
        name="mode",
        example_str="00644",
        description="File mode of file.",
        is_required=False,
        sort_order=5,
    )
    mode_op = EnumStringParameter(
        name="mode_op",
        enum_values=["equals", "not_equals"],
        example_str="equals",
        description="File mode operation to perform.",
        is_required=False,
        sort_order=6,
    )

    skip_if_file_missing = BooleanStringParameter(
        name="skip_missing",
        example_str="true",
        description="If set to true, do not fire this trigger if the file is not present.  If set to false, fire this trigger ignoring the other parameter settings.",
        is_required=False,
        sort_order=7,
    )

    def evaluate(self, image_obj, context):
        filename = self.filename.value()

        checksum_algo = self.checksum_algo.value(default_if_none="sha256")
        checksum = self.checksum.value()
        checksum_op = self.checksum_op.value(default_if_none="equals")

        mode = self.mode.value()
        mode_op = self.mode_op.value(default_if_none="equals")

        skip_if_file_missing = self.skip_if_file_missing.value(default_if_none=True)

        filedetails = {}
        if hasattr(context, "data"):
            filedetails = context.data.get("filedetail")

        fire_params = {}
        filedetail = filedetails.get(filename, None)

        if filedetail:

            # checksum checks

            if checksum and checksum_op and checksum_algo:
                file_checksum = None
                if checksum_algo == "sha256":
                    file_checksum = filedetail.get("sha256_checksum", "")

                if checksum_op == "equals" and file_checksum == checksum:
                    fire_params[
                        "checksum"
                    ] = "checksum={} op={} specified_checksum={}".format(
                        file_checksum, checksum_op, checksum
                    )
                elif checksum_op == "not_equals" and file_checksum != checksum:
                    fire_params[
                        "checksum"
                    ] = "checksum={} op={} specified_checksum={}".format(
                        file_checksum, checksum_op, checksum
                    )
                else:
                    return

            # mode checks

            if mode and mode_op:
                file_mode = filedetail.get("mode", 0)

                file_mode_cmp = oct(stat.S_IMODE(file_mode))
                input_mode_cmp = oct(int(mode, 8))

                if mode_op == "equals" and file_mode_cmp == input_mode_cmp:
                    fire_params["mode"] = "mode={} op={} specified_mode={}".format(
                        file_mode_cmp, mode_op, input_mode_cmp
                    )
                elif mode_op == "not_equals" and file_mode_cmp != input_mode_cmp:
                    fire_params["mode"] = "mode={} op={} specified_mode={}".format(
                        file_mode_cmp, mode_op, input_mode_cmp
                    )
                else:
                    return
        else:
            # case where file doesn't exist
            if skip_if_file_missing:
                return
            fire_params["skip"] = "skip_missing=False"

        if fire_params:
            msg = "filename={}".format(filename)
            for k in fire_params.keys():
                msg += " and {}".format(fire_params[k])

            self._fire(msg=msg)


class SuidCheckTrigger(BaseTrigger):
    __trigger_name__ = "suid_or_guid_set"
    __description__ = "Fires for each file found to have suid or sgid bit set."

    def evaluate(self, image_obj, context):
        if not image_obj.fs:
            return

        files = image_obj.fs.files
        if not files:
            return

        found = [
            x
            for x in list(files.items())
            if int(x[1].get("mode", 0)) & (stat.S_ISUID | stat.S_ISGID)
        ]
        for path, entry in found:
            self._fire(
                msg="SUID or SGID found set on file {}. Mode: {}".format(
                    path, oct(entry.get("mode"))
                )
            )


class FileCheckGate(Gate):
    __gate_name__ = "files"
    __description__ = "Checks against files in the analyzed image including file content, file names, and filesystem attributes."
    __triggers__ = [
        ContentMatchTrigger,
        FilenameMatchTrigger,
        FileAttributeMatchTrigger,
        SuidCheckTrigger,
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
        context.data["filenames"] = []
        context.data["filedetail"] = {}

        if image_obj.fs:
            extracted_files_json = image_obj.fs.files

            if extracted_files_json:
                context.data["filenames"] = list(extracted_files_json.keys())
                context.data["filedetail"] = extracted_files_json

        content_matches = image_obj.analysis_artifacts.filter(
            AnalysisArtifact.analyzer_id == "content_search",
            AnalysisArtifact.analyzer_artifact == "regexp_matches.all",
            AnalysisArtifact.analyzer_type == "base",
        ).all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data["content_regexp"] = matches

        return context
