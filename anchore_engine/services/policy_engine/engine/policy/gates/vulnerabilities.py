import calendar
import time

from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.db import DistroNamespace, ImageCpe, CpeVulnerability
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import BooleanStringParameter, IntegerStringParameter, EnumCommaDelimStringListParameter, EnumStringParameter, FloatStringParameter
log = get_logger()


SEVERITY_ORDERING = [
    'unknown',
    'negligible',
    'low',
    'medium',
    'high',
    'critical'
]


class VulnerabilityMatchTrigger(BaseTrigger):
    __trigger_name__ = 'package'
    __description__ = 'Triggers if a found vulnerability in an image meets the comparison criteria.'

    SEVERITY_COMPARISONS = {
        '=': lambda x, y: x == y,
        '!=': lambda x, y: x != y,
        '<': lambda x, y: x < y,
        '>': lambda x, y: x > y,
        '<=': lambda x, y: x <= y,
        '>=': lambda x, y: x >= y
    }


    package_type = EnumStringParameter(name='package_type', example_str='all', enum_values=['all', 'os', 'non-os'], description='Only trigger for specific package type.', is_required=True, sort_order=1)

    severity_comparison = EnumStringParameter(name='severity_comparison', example_str='>', description='The type of comparison to perform for severity evaluation.', enum_values=list(SEVERITY_COMPARISONS.keys()), is_required=False, sort_order=2)
    severity = EnumStringParameter(name='severity', example_str='high', description='Severity to compare against.', enum_values=SEVERITY_ORDERING, is_required=False, sort_order=3)

    cvss_baseScore_comparison = EnumStringParameter(name='cvssV3_baseScore_comparison', example_str='>', description='The type of comparison to perform for CVSSV3 baseScore evaluation.', enum_values=list(SEVERITY_COMPARISONS.keys()), is_required=False, sort_order=4)
    cvss_baseScore = FloatStringParameter(name='cvssV3_baseScore', example_string='5.0', description='CVSSV3 baseScore to compare against.', is_required=False, sort_order=5)

    cvss_exploitabilityScore_comparison = EnumStringParameter(name='cvssV3_exploitabilityScore_comparison', example_str='>', description='The type of comparison to perform for CVSSV3 exploitabilityScore evaluation.', enum_values=list(SEVERITY_COMPARISONS.keys()), is_required=False, sort_order=6)
    cvss_exploitabilityScore = FloatStringParameter(name='cvssV3_exploitabilityScore', example_string='5.0', description='CVSSV3 exploitabilityScore to compare against.', is_required=False, sort_order=7)

    cvss_impactScore_comparison = EnumStringParameter(name='cvssV3_impactScore_comparison', example_str='>', description='The type of comparison to perform for CVSSV3 impactScore evaluation.', enum_values=list(SEVERITY_COMPARISONS.keys()), is_required=False, sort_order=8)
    cvss_impactScore = FloatStringParameter(name='cvssV3_impactScore', example_string='5.0', description='CVSSV3 impactScore to compare against.', is_required=False, sort_order=9)

    fix_available = BooleanStringParameter(name='fix_available', example_str='true', description='If present, the fix availability for the vulnerability record must match the value of this parameter.', is_required=False, sort_order=10)
    vendor_only = BooleanStringParameter(name='vendor_only', example_str='true', description='If True, an available fix for this CVE must not be explicitly marked as wont be addressed by the vendor', is_required=False, sort_order=11)
    max_days_since_creation = IntegerStringParameter(name='max_days_since_creation', example_str='7', description='If provided, this CVE must be older than the days provided to trigger.', is_required=False, sort_order=12)
    max_days_since_fix = IntegerStringParameter(name='max_days_since_fix', example_str='30', description='If provided, this CVE must have a fix available, first observed more than the days provided, to trigger.', is_required=False, sort_order=13)

    def evaluate(self, image_obj, context):
        is_fix_available = self.fix_available.value()
        is_vendor_only = self.vendor_only.value(default_if_none=True)
        comparison_idx = SEVERITY_ORDERING.index(self.severity.value(default_if_none='unknown').lower())
        comparison_fn = self.SEVERITY_COMPARISONS.get(self.severity_comparison.value(default_if_none=">"))

        cvss_baseScore = self.cvss_baseScore.value()
        cvss_baseScore_comparison_fn = self.SEVERITY_COMPARISONS.get(self.cvss_baseScore_comparison.value(default_if_none=">="))
        
        cvss_exploitabilityScore = self.cvss_exploitabilityScore.value()
        cvss_exploitabilityScore_comparison_fn = self.SEVERITY_COMPARISONS.get(self.cvss_exploitabilityScore_comparison.value(default_if_none=">="))

        cvss_impactScore = self.cvss_impactScore.value()
        cvss_impactScore_comparison_fn = self.SEVERITY_COMPARISONS.get(self.cvss_impactScore_comparison.value(default_if_none=">="))

        timeallowed = time.time()
        if self.max_days_since_creation.value() is not None:
            timeallowed -= int(int(self.max_days_since_creation.value()) * 86400)

        fix_timeallowed = time.time()
        if self.max_days_since_fix.value() is not None:
            fix_timeallowed -= int(int(self.max_days_since_fix.value()) * 86400)


        if not comparison_fn:
            pass
            #raise KeyError(self.severity_comparison)

        if self.package_type.value() in ['all', 'non-os']:
            cpevulns = context.data.get('loaded_cpe_vulnerabilities')
            if cpevulns:
                try:
                    for sev in list(cpevulns.keys()):
                        found_severity_idx = SEVERITY_ORDERING.index(sev.lower()) if sev else 0
                        if comparison_fn(found_severity_idx, comparison_idx):
                            for image_cpe, vulnerability_cpe in cpevulns[sev]:
                                # Check if the vulnerability is too recent for this policy
                                if calendar.timegm(vulnerability_cpe.created_at.timetuple()) > timeallowed:
                                    continue

                                # TODO fix handler for CPE-based vuln matches (currently not enough info for fix available)

                                cvss_msg = ''
                                if cvss_baseScore is not None:
                                    vuln_cvss_baseScore = vulnerability_cpe.parent.get_baseScore()
                                    if not cvss_baseScore_comparison_fn(vuln_cvss_baseScore, cvss_baseScore):
                                        log.debug("vulnerability cvss V3 baseScore {} is not {} than policy cvss V3 baseScore {}, skipping".format(vuln_cvss_baseScore, self.cvss_baseScore_comparison.value(), cvss_baseScore))
                                        continue
                                    else:
                                        cvss_msg += ' cvssV3_baseScore={}'.format(vuln_cvss_baseScore)

                                if cvss_exploitabilityScore is not None:
                                    vuln_cvss_exploitabilityScore = vulnerability_cpe.parent.get_exploitabilityScore()
                                    if not cvss_exploitabilityScore_comparison_fn(vuln_cvss_exploitabilityScore, cvss_exploitabilityScore):
                                        log.debug("vulnerability cvss V3 exploitabilityScore {} is not {} than policy cvss V3 exploitabilityScore {}, skipping".format(vuln_cvss_exploitabilityScore, self.cvss_exploitabilityScore_comparison.value(), cvss_exploitabilityScore))
                                        continue
                                    else:
                                        cvss_msg += ' cvssV3_explotabilityScore={}'.format(vuln_cvss_exploitabilityScore)

                                if cvss_impactScore is not None:
                                    vuln_cvss_impactScore = vulnerability_cpe.parent.get_impactScore()
                                    if not cvss_impactScore_comparison_fn(vuln_cvss_impactScore, cvss_impactScore):
                                        log.debug("vulnerability cvss V3 impactScore {} is not {} than policy cvss V3 impactScore {}, skipping".format(vuln_cvss_impactScore, self.cvss_impactScore_comparison.value(), cvss_impactScore))
                                        continue
                                    else:
                                        cvss_msg += ' cvssV3_impactScore={}'.format(vuln_cvss_impactScore)

                                trigger_fname = None
                                if image_cpe.pkg_type in ['java', 'gem']:
                                    try:
                                        trigger_fname = image_cpe.pkg_path.split("/")[-1]
                                    except:
                                        trigger_fname = None
                                elif image_cpe.pkg_type in ['npm']:
                                    try:
                                        trigger_fname = image_cpe.pkg_path.split("/")[-2]
                                    except:
                                        trigger_fname = None                                    

                                if not trigger_fname:
                                    trigger_fname = "-".join([image_cpe.name, image_cpe.version])

                                if is_fix_available is not None:
                                    # Must to a fix_available check
                                    fix_available_in = image_cpe.fixed_in()
                                    if is_fix_available == (fix_available_in is not None):                                    
                                        message = sev.upper() + cvss_msg + " Vulnerability found in non-os package type ("+image_cpe.pkg_type+") - " + \
                                                  image_cpe.pkg_path + " (" + vulnerability_cpe.vulnerability_id + " - https://nvd.nist.gov/vuln/detail/" + vulnerability_cpe.vulnerability_id + ")"
                                        self._fire(instance_id=vulnerability_cpe.vulnerability_id + '+' + trigger_fname, msg=message)
                                else:
                                    message = sev.upper() + cvss_msg + " Vulnerability found in non-os package type ("+image_cpe.pkg_type+") - " + \
                                              image_cpe.pkg_path + " (" + vulnerability_cpe.vulnerability_id + " - https://nvd.nist.gov/vuln/detail/" + vulnerability_cpe.vulnerability_id + ")"
                                    self._fire(instance_id=vulnerability_cpe.vulnerability_id + '+' + trigger_fname, msg=message)

                except Exception as err:
                    log.warn("problem during non-os vulnerability evaluation - exception: {}".format(err))

        if self.package_type.value() in ['all', 'os']:
            vulns = context.data.get('loaded_vulnerabilities')

            if vulns:
                for pkg_vuln in vulns:
                    # Filter by level first
                    found_severity_idx = SEVERITY_ORDERING.index(pkg_vuln.vulnerability.severity.lower()) if pkg_vuln.vulnerability.severity else 0

                    if comparison_fn(found_severity_idx, comparison_idx):
                        # Check vendor_only flag specified by the user in policy
                        if is_vendor_only and pkg_vuln.fix_has_no_advisory():
                            # skip this vulnerability
                            continue

                        # Check if the vulnerability is to recent for this policy
                        if calendar.timegm(pkg_vuln.vulnerability.created_at.timetuple()) > timeallowed:
                            continue

                        fix_msg = ''
                        fix = pkg_vuln.fixed_artifact()
                        if fix.version and fix.version != 'None':
                            if fix.fix_observed_at and calendar.timegm(fix.fix_observed_at.timetuple()) > fix_timeallowed:
                                continue
                            else:
                                fix_msg = '(fix available since {})'.format(fix.fix_observed_at)
                        else:
                            pass
                        
                        vuln_cvss_baseScore = -1.0
                        vuln_cvss_exploitabilityScore = -1.0
                        vuln_cvss_impactScore = -1.0
                        
                        for nvd_record in pkg_vuln.vulnerability.get_nvd_vulnerabilities():
                            cvss_scores = nvd_record.get_cvssScores()
                            if cvss_scores.get('baseScore', -1.0) > vuln_cvss_baseScore:
                                vuln_cvss_baseScore = cvss_scores.get('baseScore', -1.0)
                            if cvss_scores.get('exploitabilityScore', -1.0) > vuln_cvss_exploitabilityScore:
                                vuln_cvss_exploitabilityScore = cvss_scores.get('exploitabilityScore', -1.0)
                            if cvss_scores.get('impactScore', -1.0) > vuln_cvss_impactScore:
                                vuln_cvss_impactScore = cvss_scores.get('impactScore', -1.0)

                        cvss_msg = ''
                        if cvss_baseScore is not None:
                            if not cvss_baseScore_comparison_fn(vuln_cvss_baseScore, cvss_baseScore):
                                log.debug("OS vulnerability cvss V3 baseScore {} is not {} than policy cvss V3 baseScore {}, skipping".format(vuln_cvss_baseScore, self.cvss_baseScore_comparison.value(), cvss_baseScore))
                                continue
                            else:
                                cvss_msg += ' cvssV3_baseScore={}'.format(vuln_cvss_baseScore)

                        if cvss_exploitabilityScore is not None:
                            if not cvss_exploitabilityScore_comparison_fn(vuln_cvss_exploitabilityScore, cvss_exploitabilityScore):
                                log.debug("OS vulnerability cvss V3 exploitabilityScore {} is not {} than policy cvss V3 exploitabilityScore {}, skipping".format(vuln_cvss_exploitabilityScore, self.cvss_exploitabilityScore_comparison.value(), cvss_exploitabilityScore))
                                continue
                            else:
                                cvss_msg += ' cvssV3_explotabilityScore={}'.format(vuln_cvss_exploitabilityScore)

                        if cvss_impactScore is not None:
                            if not cvss_impactScore_comparison_fn(vuln_cvss_impactScore, cvss_impactScore):
                                log.debug("OS vulnerability cvss V3 impactScore {} is not {} than policy cvss V3 impactScore {}, skipping".format(vuln_cvss_impactScore, self.cvss_impactScore_comparison.value(), cvss_impactScore))
                                continue
                            else:
                                cvss_msg += ' cvssV3_impactScore={}'.format(vuln_cvss_impactScore)


                        # Check fix_available status if specified by user in policy
                        if is_fix_available is not None:
                            # Must to a fix_available check
                            fix_available_in = pkg_vuln.fixed_in()

                            if is_fix_available == (fix_available_in is not None):
                                # explicit fix state check matches fix availability
                                if is_fix_available:
                                    message = pkg_vuln.vulnerability.severity.upper() + cvss_msg + " " + fix_msg + " Vulnerability found in os package type ("+pkg_vuln.pkg_type+") - " + \
                                              pkg_vuln.pkg_name + " (fixed in: {}".format(fix_available_in) + ") - (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                                else:
                                    message = pkg_vuln.vulnerability.severity.upper() + cvss_msg + " " + fix_msg + " Vulnerability found in os package type ("+pkg_vuln.pkg_type+") - " + \
                                              pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"

                                self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)
                        else:
                            # No fix status check since not specified by user
                            message = pkg_vuln.vulnerability.severity.upper() + cvss_msg + " " + fix_msg + " Vulnerability found in os package type ("+pkg_vuln.pkg_type+") - " + \
                                      pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                            self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)


class FeedOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'stale_feed_data'
    __description__ = 'Triggers if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days).'
    max_age = IntegerStringParameter(name='max_days_since_sync', example_str='10', description='Fire the trigger if the last sync was more than this number of days ago.', is_required=True)

    def evaluate(self, image_obj, context):
        # Map to a namespace
        ns = DistroNamespace.for_obj(image_obj)

        oldest_update = None
        if ns:
            vulnerability_feed = DataFeeds.instance().vulnerabilities
            for namespace_name in ns.like_namespace_names:
                # Check feed names
                groups = vulnerability_feed.group_by_name(namespace_name)
                if groups:
                    # No records yet, but we have the feed, so may just not have any data yet
                    oldest_update = groups[0].last_sync
                    break

        if self.max_age.value() is not None:
            try:
                if oldest_update is not None:
                    oldest_update = calendar.timegm(oldest_update.timetuple())
                    mintime = time.time() - int(int(self.max_age.value()) * 86400)
                    if oldest_update < mintime:
                        self._fire(msg="The vulnerability feed for this image distro is older than MAXAGE ("+str(self.max_age.value())+") days")
                else:
                    self._fire(
                        msg="The vulnerability feed for this image distro is older than MAXAGE (" + str(self.max_age.value()) + ") days")
            except Exception as err:
                self._fire(msg="Cannot perform data feed up-to-date check - message from server: " + str(err))


class UnsupportedDistroTrigger(BaseTrigger):
    __trigger_name__ = 'vulnerability_data_unavailable'
    __description__ = "Triggers if vulnerability data is unavailable for the image's distro."

    def evaluate(self, image_obj, context):
        if not have_vulnerabilities_for(DistroNamespace.for_obj(image_obj)):
            self._fire(msg="Feed data unavailable, cannot perform CVE scan for distro: "+str(image_obj.distro_namespace))


class VulnerabilitiesGate(Gate):
    __gate_name__ = 'vulnerabilities'
    __description__ = 'CVE/Vulnerability checks.'
    __triggers__ = [
        VulnerabilityMatchTrigger,
        FeedOutOfDateTrigger,
        UnsupportedDistroTrigger
    ]

    def prepare_context(self, image_obj, context):
        """

        :rtype:
        """
        # Load the package vulnerability info up front
        pkg_vulns = image_obj.vulnerabilities()
        context.data['loaded_vulnerabilities'] = pkg_vulns

        # Load the non-package (CPE) vulnerability info up front
        all_cpe_matches = image_obj.cpe_vulnerabilities()
        if not all_cpe_matches:
            all_cpe_matches = []

        dedup_hash = {}
        severity_matches = {}
        for image_cpe, vulnerability_cpe in all_cpe_matches:
            sev = vulnerability_cpe.severity
            if sev not in severity_matches:
                severity_matches[sev] = []
            
            if image_cpe.pkg_path:
                if image_cpe.pkg_path not in dedup_hash:
                    dedup_hash[image_cpe.pkg_path] = []

                if vulnerability_cpe.vulnerability_id not in dedup_hash[image_cpe.pkg_path]:
                    dedup_hash[image_cpe.pkg_path].append(vulnerability_cpe.vulnerability_id)
                    severity_matches[sev].append((image_cpe, vulnerability_cpe))
            else:
                severity_matches[sev].append((image_cpe, vulnerability_cpe))

        context.data['loaded_cpe_vulnerabilities'] = severity_matches

        return context
