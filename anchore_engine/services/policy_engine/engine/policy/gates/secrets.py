import re
import base64
from anchore_engine.utils import ensure_bytes, ensure_str
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.params import (
    TypeValidator,
    TriggerParameter,
    EnumStringParameter,
)
from anchore_engine.db import AnalysisArtifact


default_included_regex_names = [
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "PRIV_KEY",
    "DOCKER_AUTH",
    "API_KEY",
]


class SecretContentChecksTrigger(BaseTrigger):
    __trigger_name__ = "content_regex_checks"
    __description__ = 'Triggers if the secret content search analyzer has found any matches with the configured and named regexes. Checks can be configured to trigger if a match is found or is not found (selected using match_type parameter).  Matches are filtered by the content_regex_name and filename_regex if they are set. The content_regex_name shoud be a value from the "secret_search" section of the analyzer_config.yaml.'

    secret_contentregexp = TriggerParameter(
        name="content_regex_name",
        validator=TypeValidator("string"),
        example_str=default_included_regex_names[0],
        description="Name of content regexps configured in the analyzer that match if found in the image, instead of matching all. Names available by default are: {}.".format(
            default_included_regex_names
        ),
        sort_order=1,
    )
    name_regexps = TriggerParameter(
        name="filename_regex",
        validator=TypeValidator("string"),
        example_str="/etc/.*",
        description="Regexp to filter the content matched files by.",
        sort_order=2,
    )
    match_type = EnumStringParameter(
        name="match_type",
        enum_values=["notfound", "found"],
        example_str="found",
        description="Set to define the type of match - trigger if match is found (default) or not found.",
        is_required=False,
        sort_order=3,
    )

    def evaluate(self, image_obj, context):
        match_filter = self.secret_contentregexp.value(default_if_none=[])
        name_filter = self.name_regexps.value()
        name_re = re.compile(name_filter) if self.name_regexps.value() else None
        match_type = self.match_type.value(default_if_none="found")

        if match_filter:
            matches = [base64.b64encode(ensure_bytes(x)) for x in match_filter]
            matches_decoded = match_filter
        else:
            matches = []
            matches_decoded = []

        onefound = False
        for thefile, regexps in list(
            context.data.get("secret_content_regexp", {}).items()
        ):
            thefile = ensure_str(thefile)

            if not regexps:
                continue

            if regexps and (not name_re or name_re.match(thefile)):
                for regexp in list(regexps.keys()):
                    found = False
                    decoded_regexp = ensure_str(base64.b64decode(ensure_bytes(regexp)))

                    try:
                        regexp_name, theregexp = decoded_regexp.split("=", 1)
                    except:
                        regexp_name = None
                        theregexp = decoded_regexp

                    if not matches:
                        found = onefound = True
                    elif regexp in matches or theregexp in matches_decoded:
                        found = onefound = True
                    elif regexp_name and regexp_name in matches_decoded:
                        found = onefound = True

                    if found and match_type == "found":
                        self._fire(
                            msg="Secret content search analyzer found regexp match in container: file={} regexp={}".format(
                                thefile, decoded_regexp
                            )
                        )

        if not onefound and match_type == "notfound":
            f_filter = name_filter
            if not f_filter:
                f_filter = "*"

            m_filter = match_filter
            if not m_filter:
                m_filter = "all"
            self._fire(
                msg="Secret content search analyzer did not find regexp match in container: filename_regex={} content_regex_name={}".format(
                    f_filter, m_filter
                )
            )


class SecretCheckGate(Gate):
    __gate_name__ = "secret_scans"
    __description__ = 'Checks for secrets and content found in the image using configured regexes found in the "secret_search" section of analyzer_config.yaml.'
    __triggers__ = [SecretContentChecksTrigger]

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
                context.data["filenames"] = list(extracted_files_json.keys())

        content_matches = image_obj.analysis_artifacts.filter(
            AnalysisArtifact.analyzer_id == "secret_search",
            AnalysisArtifact.analyzer_artifact == "regexp_matches.all",
            AnalysisArtifact.analyzer_type == "base",
        ).all()
        matches = {}
        for m in content_matches:
            matches[m.artifact_key] = m.json_value
        context.data["secret_content_regexp"] = matches

        return context
