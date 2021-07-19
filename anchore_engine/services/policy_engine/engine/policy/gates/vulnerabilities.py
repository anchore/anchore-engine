import calendar
import re
import time
from collections import OrderedDict

from anchore_engine.common import nonos_package_types
from anchore_engine.db import DistroNamespace
from anchore_engine.db.entities.common import get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.feeds.db import (
    get_feed_group_detached,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    feed_registry,
    have_vulnerabilities_for,
)
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    BooleanStringParameter,
    CommaDelimitedStringListParameter,
    EnumStringParameter,
    FloatStringParameter,
    IntegerStringParameter,
    SimpleStringParameter,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import (
    get_vulnerabilities_provider,
)
from anchore_engine.subsys import logger

SEVERITY_ORDERING = ["unknown", "negligible", "low", "medium", "high", "critical"]


class VulnerabilityMatchTrigger(BaseTrigger):
    __trigger_name__ = "package"
    __description__ = (
        "Triggers if a found vulnerability in an image meets the comparison criteria."
    )

    SEVERITY_COMPARISONS = {
        "=": lambda x, y: x == y,
        "!=": lambda x, y: x != y,
        "<": lambda x, y: x < y,
        ">": lambda x, y: x > y,
        "<=": lambda x, y: x <= y,
        ">=": lambda x, y: x >= y,
    }

    package_type = EnumStringParameter(
        name="package_type",
        example_str="all",
        enum_values=["all", "os", "non-os"],
        description="Only trigger for specific package type.",
        is_required=True,
        sort_order=1,
    )

    severity_comparison = EnumStringParameter(
        name="severity_comparison",
        example_str=">",
        description="The type of comparison to perform for severity evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=2,
    )
    severity = EnumStringParameter(
        name="severity",
        example_str="high",
        description="Severity to compare against.",
        enum_values=SEVERITY_ORDERING,
        is_required=False,
        sort_order=3,
    )

    cvss_v3_base_score_comparison = EnumStringParameter(
        name="cvss_v3_base_score_comparison",
        example_str=">",
        description="The type of comparison to perform for CVSS v3 base score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=4,
    )
    cvss_v3_base_score = FloatStringParameter(
        name="cvss_v3_base_score",
        example_string="5.0",
        description="CVSS v3 base score to compare against.",
        is_required=False,
        sort_order=5,
    )

    cvss_v3_exploitability_score_comparison = EnumStringParameter(
        name="cvss_v3_exploitability_score_comparison",
        example_str=">",
        description="The type of comparison to perform for CVSS v3 exploitability sub score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=6,
    )
    cvss_v3_exploitability_score = FloatStringParameter(
        name="cvss_v3_exploitability_score",
        example_string="5.0",
        description="CVSS v3 exploitability sub score to compare against.",
        is_required=False,
        sort_order=7,
    )

    cvss_v3_impact_score_comparison = EnumStringParameter(
        name="cvss_v3_impact_score_comparison",
        example_str=">",
        description="The type of comparison to perform for CVSS v3 impact sub score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=8,
    )
    cvss_v3_impact_score = FloatStringParameter(
        name="cvss_v3_impact_score",
        example_string="5.0",
        description="CVSS v3 impact sub score to compare against.",
        is_required=False,
        sort_order=9,
    )

    fix_available = BooleanStringParameter(
        name="fix_available",
        example_str="true",
        description="If present, the fix availability for the vulnerability record must match the value of this parameter.",
        is_required=False,
        sort_order=10,
    )
    vendor_only = BooleanStringParameter(
        name="vendor_only",
        example_str="true",
        description="If True, an available fix for this CVE must not be explicitly marked as wont be addressed by the vendor",
        is_required=False,
        sort_order=11,
    )
    max_days_since_creation = IntegerStringParameter(
        name="max_days_since_creation",
        example_str="7",
        description="If provided, this CVE must be older than the days provided to trigger.",
        is_required=False,
        sort_order=12,
    )
    max_days_since_fix = IntegerStringParameter(
        name="max_days_since_fix",
        example_str="30",
        description="If provided (only evaluated when fix_available option is also set to true), the fix first observed time must be older than days provided, to trigger.",
        is_required=False,
        sort_order=13,
    )

    vendor_cvss_v3_base_score_comparison = EnumStringParameter(
        name="vendor_cvss_v3_base_score_comparison",
        example_str=">",
        description="The type of comparison to perform for vendor specified CVSS v3 base score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=14,
    )
    vendor_cvss_v3_base_score = FloatStringParameter(
        name="vendor_cvss_v3_base_score",
        example_string="5.0",
        description="Vendor CVSS v3 base score to compare against.",
        is_required=False,
        sort_order=15,
    )

    vendor_cvss_v3_exploitability_score_comparison = EnumStringParameter(
        name="vendor_cvss_v3_exploitability_score_comparison",
        example_str=">",
        description="The type of comparison to perform for vendor specified CVSS v3 exploitability sub score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=16,
    )
    vendor_cvss_v3_exploitability_score = FloatStringParameter(
        name="vendor_cvss_v3_exploitability_score",
        example_string="5.0",
        description="Vendor CVSS v3 exploitability sub score to compare against.",
        is_required=False,
        sort_order=17,
    )

    vendor_cvss_v3_impact_score_comparison = EnumStringParameter(
        name="vendor_cvss_v3_impact_score_comparison",
        example_str=">",
        description="The type of comparison to perform for vendor specified CVSS v3 impact sub score evaluation.",
        enum_values=list(SEVERITY_COMPARISONS.keys()),
        is_required=False,
        sort_order=18,
    )
    vendor_cvss_v3_impact_score = FloatStringParameter(
        name="vendor_cvss_v3_impact_score",
        example_string="5.0",
        description="Vendor CVSS v3 impact sub score to compare against.",
        is_required=False,
        sort_order=19,
    )

    package_path_exclude = SimpleStringParameter(
        name="package_path_exclude",
        example_str=".*test\.jar*",
        description="The regex to evaluate against the package path to exclude vulnerabilities",
        is_required=False,
        sort_order=20,
    )

    def evaluate(self, image_obj, context):
        is_fix_available = self.fix_available.value()
        is_vendor_only = self.vendor_only.value(default_if_none=True)
        comparison_idx = SEVERITY_ORDERING.index(
            self.severity.value(default_if_none="unknown").lower()
        )
        comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.severity_comparison.value(default_if_none=">")
        )

        cvss_v3_base_score = self.cvss_v3_base_score.value()
        cvss_v3_base_score_comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.cvss_v3_base_score_comparison.value(default_if_none=">=")
        )

        cvss_v3_exploitability_score = self.cvss_v3_exploitability_score.value()
        cvss_v3_exploitability_score_comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.cvss_v3_exploitability_score_comparison.value(default_if_none=">=")
        )

        cvss_v3_impact_score = self.cvss_v3_impact_score.value()
        cvss_v3_impact_score_comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.cvss_v3_impact_score_comparison.value(default_if_none=">=")
        )

        now = time.time()

        timeallowed = None
        if self.max_days_since_creation.value() is not None:
            timeallowed = now - int(int(self.max_days_since_creation.value()) * 86400)

        fix_timeallowed = None
        if self.max_days_since_fix.value() is not None:
            fix_timeallowed = now - int(int(self.max_days_since_fix.value()) * 86400)

        if not comparison_fn:
            pass
            # raise KeyError(self.severity_comparison)

        vendor_cvss_v3_base_score = self.vendor_cvss_v3_base_score.value()
        vendor_cvss_v3_base_score_comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.vendor_cvss_v3_base_score_comparison.value(default_if_none=">=")
        )

        vendor_cvss_v3_exploitability_score = (
            self.vendor_cvss_v3_exploitability_score.value()
        )
        vendor_cvss_v3_exploitability_score_comparison_fn = (
            self.SEVERITY_COMPARISONS.get(
                self.vendor_cvss_v3_exploitability_score_comparison.value(
                    default_if_none=">="
                )
            )
        )

        vendor_cvss_v3_impact_score = self.vendor_cvss_v3_impact_score.value()
        vendor_cvss_v3_impact_score_comparison_fn = self.SEVERITY_COMPARISONS.get(
            self.vendor_cvss_v3_impact_score_comparison.value(default_if_none=">=")
        )

        package_path_re = None
        path_exclude_re_value = self.package_path_exclude.value()
        if path_exclude_re_value is not None:
            package_path_re = re.compile(path_exclude_re_value)

        vuln_matches = context.data.get("loaded_vulnerabilities")

        if vuln_matches:
            pkg_type_value = self.package_type.value()

            for vuln_match in vuln_matches:
                vulnerability_obj = vuln_match.vulnerability
                artifact_obj = vuln_match.artifact
                fix_obj = vuln_match.fix
                match_obj = vuln_match.match
                nvd_cvss_objects = vuln_match.get_cvss_scores_nvd()
                vendor_cvss_objects = vuln_match.get_cvss_scores_vendor()

                new_vuln_pkg_class = (
                    "non-os"
                    if artifact_obj.pkg_type.lower() in nonos_package_types
                    else "os"
                )

                # Filter first by package class, if rule has a filter
                if pkg_type_value != "all" and pkg_type_value != new_vuln_pkg_class:
                    logger.debug(
                        "Gate package type {} is not a match for artifact package type {}, skipping".format(
                            pkg_type_value, artifact_obj.pkg_type
                        )
                    )
                    # don't process the vulnerability if the affected package type is not a match for the gate
                    continue

                # Start constructing gate parameter data
                parameter_data = OrderedDict()

                parameter_data["severity"] = vulnerability_obj.severity.upper()
                parameter_data["vulnerability_id"] = vulnerability_obj.vulnerability_id
                parameter_data["pkg_type"] = artifact_obj.pkg_type
                parameter_data["pkg_class"] = new_vuln_pkg_class

                # setting fixed_version here regardless of gate parameter,
                fix_versions = [version for version in fix_obj.versions if version]
                fix_available_in = ", ".join(fix_versions) if fix_versions else None

                if fix_available_in:
                    parameter_data["fixed_version"] = fix_available_in

                # Filter by level first
                found_severity_idx = (
                    SEVERITY_ORDERING.index(vulnerability_obj.severity.lower())
                    if vulnerability_obj.severity
                    else 0
                )
                if comparison_fn(found_severity_idx, comparison_idx):
                    # package path excludes logic for non-os packages only
                    if new_vuln_pkg_class == "non-os" and package_path_re:
                        match_found = package_path_re.match(artifact_obj.location)
                        if match_found is not None:
                            logger.debug(
                                "Non-OS vulnerability {} package path {} matches package path exclude {}, skipping".format(
                                    artifact_obj.name,
                                    artifact_obj.location,
                                    path_exclude_re_value,
                                )
                            )
                            continue

                    # Check vendor_only flag specified by the user in policy
                    if is_vendor_only:
                        if fix_obj.wont_fix:
                            logger.debug(
                                "{} vulnerability {} for package {} is marked by vendor as won't fix, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    artifact_obj.name,
                                )
                            )
                            continue

                    # Check if the vulnerability is to recent for this policy
                    if timeallowed:
                        if (
                            calendar.timegm(match_obj.detected_at.timetuple())
                            > timeallowed
                        ):
                            continue
                        parameter_data[
                            "max_days_since_creation"
                        ] = match_obj.detected_at.date()

                    if is_fix_available and fix_timeallowed is not None:
                        fix_observed_at = (
                            fix_obj.observed_at if fix_available_in else None
                        )

                        if fix_observed_at:
                            if (
                                calendar.timegm(fix_observed_at.timetuple())
                                > fix_timeallowed
                            ):
                                continue
                            else:
                                parameter_data[
                                    "max_days_since_fix"
                                ] = fix_observed_at.date()

                    vuln_cvss_base_score = -1.0
                    vuln_cvss_exploitability_score = -1.0
                    vuln_cvss_impact_score = -1.0

                    # Gather cvss scores before operating with max
                    nvd_cvss_v3_scores = []
                    for cvss_obj in nvd_cvss_objects:
                        if cvss_obj.version.startswith("3"):
                            nvd_cvss_v3_scores.append(cvss_obj)

                    # Compute max score for each type
                    if nvd_cvss_v3_scores:
                        vuln_cvss_base_score = max(
                            item.base_score for item in nvd_cvss_v3_scores
                        )
                        vuln_cvss_exploitability_score = max(
                            item.exploitability_score for item in nvd_cvss_v3_scores
                        )
                        vuln_cvss_impact_score = max(
                            item.impact_score for item in nvd_cvss_v3_scores
                        )

                    if cvss_v3_base_score is not None:
                        if not cvss_v3_base_score_comparison_fn(
                            vuln_cvss_base_score, cvss_v3_base_score
                        ):
                            logger.debug(
                                "{} vulnerability {} cvss V3 base_score {} is not {} than policy cvss V3 base_score {}, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    vuln_cvss_base_score,
                                    self.cvss_v3_base_score_comparison.value(),
                                    cvss_v3_base_score,
                                )
                            )
                            continue
                        else:
                            parameter_data["cvss_v3_base_score"] = vuln_cvss_base_score

                    if cvss_v3_exploitability_score is not None:
                        if not cvss_v3_exploitability_score_comparison_fn(
                            vuln_cvss_exploitability_score, cvss_v3_exploitability_score
                        ):
                            logger.debug(
                                "{} vulnerability {} cvss V3 exploitability_score {} is not {} than policy cvss V3 exploitability_score {}, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    vuln_cvss_exploitability_score,
                                    self.cvss_v3_exploitability_score_comparison.value(),
                                    cvss_v3_exploitability_score,
                                )
                            )
                            continue
                        else:
                            parameter_data[
                                "cvss_v3_exploitability_score"
                            ] = vuln_cvss_exploitability_score

                    if cvss_v3_impact_score is not None:
                        if not cvss_v3_impact_score_comparison_fn(
                            vuln_cvss_impact_score, cvss_v3_impact_score
                        ):
                            logger.debug(
                                "{} vulnerability {} cvss V3 impact_score {} is not {} than policy cvss V3 impact_score {}, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    vuln_cvss_impact_score,
                                    self.cvss_v3_impact_score_comparison.value(),
                                    cvss_v3_impact_score,
                                )
                            )
                            continue
                        else:
                            parameter_data[
                                "cvss_v3_impact_score"
                            ] = vuln_cvss_impact_score

                    # Check fix_available status if specified by user in policy
                    if is_fix_available is not None:
                        # explicit fix state check matches fix availability
                        if is_fix_available != (fix_available_in is not None):
                            # if_fix_available is set but does not match is_fix_available check
                            continue

                    parameter_data["link"] = vulnerability_obj.link

                    fix_msg = ""
                    if parameter_data.get("fixed_version", None):
                        fix_msg = "(fixed in: {})".format(
                            parameter_data.get("fixed_version")
                        )

                    score_msg = ""
                    score_tuples = []
                    for s in [
                        "cvss_v3_base_score",
                        "cvss_v3_exploitability_score",
                        "cvss_v3_impact_score",
                    ]:
                        if parameter_data.get(s, None):
                            score_tuples.append(
                                "{}={}".format(s, parameter_data.get(s))
                            )
                    if score_tuples:
                        score_msg = "({})".format(" ".join(score_tuples))

                    time_msg = ""
                    time_tuples = []
                    for s in ["max_days_since_creation", "max_days_since_fix"]:
                        if parameter_data.get(s, None):
                            time_tuples.append("{}={}".format(s, parameter_data.get(s)))
                    if time_tuples:
                        time_msg = "({})".format(" ".join(time_tuples))

                    # process vendor CVSS scores
                    vuln_vendor_cvss_base_score = -1.0
                    vuln_vendor_cvss_exploitability_score = -1.0
                    vuln_vendor_cvss_impact_score = -1.0

                    # Gather cvss scores before operating with max
                    vendor_cvss_v3_scores = []
                    for score_obj in vendor_cvss_objects:
                        if score_obj.version.startswith("3"):
                            vendor_cvss_v3_scores.append(score_obj)

                    if vendor_cvss_v3_scores:
                        vuln_vendor_cvss_base_score = max(
                            item.base_score for item in vendor_cvss_v3_scores
                        )
                        vuln_vendor_cvss_exploitability_score = max(
                            item.exploitability_score for item in vendor_cvss_v3_scores
                        )
                        vuln_vendor_cvss_impact_score = max(
                            item.impact_score for item in vendor_cvss_v3_scores
                        )

                    if vendor_cvss_v3_base_score is not None:
                        if not vendor_cvss_v3_base_score_comparison_fn(
                            vuln_vendor_cvss_base_score, vendor_cvss_v3_base_score
                        ):
                            logger.debug(
                                "{} vulnerability {} vendor cvss V3 base score {} is not {} than policy vendor cvss V3 base score {}, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    vuln_vendor_cvss_base_score,
                                    self.vendor_cvss_v3_base_score_comparison.value(),
                                    vendor_cvss_v3_base_score,
                                )
                            )
                            continue
                        else:
                            parameter_data[
                                "vendor_cvss_v3_base_score"
                            ] = vuln_vendor_cvss_base_score

                    if vendor_cvss_v3_exploitability_score is not None:
                        if not vendor_cvss_v3_exploitability_score_comparison_fn(
                            vuln_vendor_cvss_exploitability_score,
                            vendor_cvss_v3_exploitability_score,
                        ):
                            logger.debug(
                                "{} vulnerability {} vendor cvss V3 exploitability sub score {} is not {} than policy vendor cvss V3 exploitability sub score {}, skipping".format(
                                    new_vuln_pkg_class,
                                    vulnerability_obj.vulnerability_id,
                                    vuln_vendor_cvss_exploitability_score,
                                    self.vendor_cvss_v3_exploitability_score_comparison.value(),
                                    vendor_cvss_v3_exploitability_score,
                                )
                            )
                            continue
                        else:
                            parameter_data[
                                "vendor_cvss_v3_exploitability_score"
                            ] = vuln_vendor_cvss_exploitability_score

                    if vendor_cvss_v3_impact_score is not None:
                        if not vendor_cvss_v3_impact_score_comparison_fn(
                            vuln_vendor_cvss_impact_score, vendor_cvss_v3_impact_score
                        ):
                            logger.debug(
                                "%s vulnerability %s vendor cvss V3 impact sub score %d is not %s than policy vendor cvss V3 impact score %d, skipping",
                                new_vuln_pkg_class,
                                vulnerability_obj.vulnerability_id,
                                vuln_vendor_cvss_impact_score,
                                self.vendor_cvss_v3_impact_score_comparison.value(),
                                vendor_cvss_v3_impact_score,
                            )
                            continue
                        else:
                            parameter_data[
                                "vendor_cvss_v3_impact_score"
                            ] = vuln_vendor_cvss_impact_score

                    vendor_score_msg = ""
                    vendor_score_tuples = []
                    for s in [
                        "vendor_cvss_v3_base_score",
                        "vendor_cvss_v3_exploitability_score",
                        "vendor_cvss_v3_impact_score",
                    ]:
                        if parameter_data.get(s, None):
                            vendor_score_tuples.append(
                                "{}={}".format(s, parameter_data.get(s))
                            )
                    if vendor_score_tuples:
                        vendor_score_msg = "({})".format(" ".join(vendor_score_tuples))

                    # new detail message approach
                    # pkgname = pkg_vuln.pkg_name
                    # if pkg_vuln.pkg_version != 'None':
                    #    pkgname += "-{}".format(pkg_vuln.pkg_version)
                    # msg = "Vulnerability found in package {} - matching parameters: ".format(pkgname)
                    # for i in parameter_data:
                    #    msg += "{}={} ".format(i, parameter_data[i])

                    if new_vuln_pkg_class == "non-os":
                        trigger_fname = None
                        if artifact_obj.pkg_type in ["java", "gem"]:
                            try:
                                trigger_fname = artifact_obj.location.split("/")[-1]
                            except:
                                trigger_fname = None
                        elif artifact_obj.pkg_type in ["npm"]:
                            try:
                                trigger_fname = artifact_obj.location.split("/")[-2]
                            except:
                                trigger_fname = None

                        if not trigger_fname:
                            trigger_fname = "-".join(
                                [artifact_obj.name, artifact_obj.version]
                            )

                        pkgname = artifact_obj.location
                    else:
                        trigger_fname = artifact_obj.name
                        pkgname = artifact_obj.name

                    # original detail message approach
                    msg = "{} Vulnerability found in {} package type ({}) - {} {}{}{}{}({} - {})".format(
                        parameter_data["severity"].upper(),
                        parameter_data["pkg_class"],
                        parameter_data["pkg_type"],
                        pkgname,
                        fix_msg,
                        score_msg,
                        time_msg,
                        vendor_score_msg,
                        parameter_data["vulnerability_id"],
                        parameter_data["link"],
                    )

                    self._fire(
                        instance_id=vulnerability_obj.vulnerability_id
                        + "+"
                        + trigger_fname,
                        msg=msg,
                    )


class FeedOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = "stale_feed_data"
    __description__ = "Triggers if the CVE data for the image's distro is older than the window specified by the parameter MAXAGE (unit is number of days)."
    max_age = IntegerStringParameter(
        name="max_days_since_sync",
        example_str="10",
        description="Fire the trigger if the last sync was more than this number of days ago.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        # Map to a namespace
        ns = DistroNamespace.for_obj(image_obj)

        oldest_update = None
        if ns:
            for namespace_name in ns.like_namespace_names:
                # Check feed names
                for feed in feed_registry.registered_vulnerability_feed_names():
                    # First match, assume only one matches for the namespace
                    group = get_feed_group_detached(feed, namespace_name)
                    if group:
                        # No records yet, but we have the feed, so may just not have any data yet
                        oldest_update = group.last_sync
                        logger.debug(
                            "Found date for oldest update in feed %s group %s date = %s",
                            feed,
                            group.name,
                            oldest_update,
                        )
                        break

        if self.max_age.value() is not None:
            try:
                if oldest_update is not None:
                    oldest_update = calendar.timegm(oldest_update.timetuple())
                    mintime = time.time() - int(int(self.max_age.value()) * 86400)
                    if oldest_update < mintime:
                        self._fire(
                            msg="The vulnerability feed for this image distro is older than MAXAGE ("
                            + str(self.max_age.value())
                            + ") days"
                        )
                else:
                    self._fire(
                        msg="The vulnerability feed for this image distro is older than MAXAGE ("
                        + str(self.max_age.value())
                        + ") days"
                    )
            except Exception as err:
                self._fire(
                    msg="Cannot perform data feed up-to-date check - message from server: "
                    + str(err)
                )


class UnsupportedDistroTrigger(BaseTrigger):
    __trigger_name__ = "vulnerability_data_unavailable"
    __description__ = "Triggers if vulnerability data is unavailable for the image's distro packages such as rpms or dpkg. Non-OS packages like npms and java are not considered in this evaluation"

    def evaluate(self, image_obj, context):
        if not have_vulnerabilities_for(DistroNamespace.for_obj(image_obj)):
            self._fire(
                msg="Distro-specific feed data not found for distro namespace: %s. Cannot perform CVE scan OS/distro packages"
                % image_obj.distro_namespace
            )


class VulnerabilityBlacklistTrigger(BaseTrigger):
    __trigger_name__ = "blacklist"
    __description__ = "Triggers if any of a list of specified vulnerabilities has been detected in the image."

    vulnerability_ids = CommaDelimitedStringListParameter(
        name="vulnerability_ids",
        example_str="CVE-2019-1234",
        description="List of vulnerability IDs, will cause the trigger to fire if any are detected.",
        is_required=True,
        sort_order=1,
    )
    vendor_only = BooleanStringParameter(
        name="vendor_only",
        example_str="true",
        description="If set to True, discard matches against this vulnerability if vendor has marked as will not fix in the vulnerability record.",
        is_required=False,
        sort_order=2,
    )

    def evaluate(self, image_obj, context):
        vids = self.vulnerability_ids.value()
        is_vendor_only = self.vendor_only.value(default_if_none=True)

        found_vids = []

        for vid in vids:
            found = False

            matches = context.data.get("loaded_vulnerabilities")
            for match in matches:
                if is_vendor_only:
                    if match.fix.wont_fix:
                        continue
                # search for vid in all vulns
                if vid == match.vulnerability.vulnerability_id:
                    found = True
                    break

            if found:
                found_vids.append(vid)

        if found_vids:
            self._fire(
                msg="Blacklisted vulnerabilities detected: {}".format(found_vids)
            )


class VulnerabilitiesGate(Gate):
    __gate_name__ = "vulnerabilities"
    __description__ = "CVE/Vulnerability checks."
    __triggers__ = [
        VulnerabilityMatchTrigger,
        FeedOutOfDateTrigger,
        UnsupportedDistroTrigger,
        VulnerabilityBlacklistTrigger,
    ]

    def prepare_context(self, image_obj, context):
        """

        :rtype:
        """

        db_session = get_thread_scoped_session()
        vuln_report = get_vulnerabilities_provider().get_image_vulnerabilities(
            image_obj, db_session
        )
        context.data["loaded_vulnerabilities"] = vuln_report.results

        return context
