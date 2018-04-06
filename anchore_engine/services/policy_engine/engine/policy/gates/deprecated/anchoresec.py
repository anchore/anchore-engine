import calendar
import time

from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger, LifecycleStates
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.db import DistroNamespace
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import BooleanStringParameter, IntegerStringParameter

log = get_logger()


class CveSeverityTrigger(BaseTrigger):
    __vuln_levels__ = None
    fix_available = BooleanStringParameter(name='fix_available', description='If present, the fix availability for the CVE record must match the value of this parameter.', is_required=False)
    vendor_only = BooleanStringParameter(name='vendor_only', description='If True, an available fix for this CVE must not be explicitly marked as wont be addressed by the vendor', is_required=False)

    def evaluate(self, image_obj, context):
        vulns = context.data.get('loaded_vulnerabilities')
        if not vulns:
            return

        is_fix_available = self.fix_available.value()
        is_vendor_only = self.vendor_only.value(default_if_none=True)

        for pkg_vuln in vulns:
            # Filter by level first
            if pkg_vuln.vulnerability.severity in self.__vuln_levels__:

                # Check vendor_only flag specified by the user in policy
                if is_vendor_only and pkg_vuln.fix_has_no_advisory():
                    # skip this vulnerability
                    continue

                # Check fix_available status if specified by user in policy
                if is_fix_available is not None:
                    # Must to a fix_available check
                    fix_available_in = pkg_vuln.fixed_in()

                    if is_fix_available == (fix_available_in is not None):
                        # explicit fix state check matches fix availability
                        message = pkg_vuln.vulnerability.severity.upper() + " Vulnerability found in package - " + \
                                  pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                        self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)
                else:
                    # No fix status check since not specified by user
                    message = pkg_vuln.vulnerability.severity.upper() + " Vulnerability found in package - " + \
                              pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                    self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)


class LowSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'vulnlow'
    __description__ = 'Checks for "low" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Low']
    __lifecycle_state__ = LifecycleStates.deprecated


class MediumSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'vulnmedium'
    __description__ = 'Checks for "medium" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Medium']
    __lifecycle_state__ = LifecycleStates.deprecated


class HighSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'vulnhigh'
    __description__ = 'Checks for "high" severity vulnerabilities found in an image'
    __vuln_levels__ = ['High']
    __lifecycle_state__ = LifecycleStates.deprecated


class CriticalSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'vulncritical'
    __description__ = 'Checks for "critical" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Critical']
    __lifecycle_state__ = LifecycleStates.deprecated


class UnknownSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'vulnunknown'
    __description__ = 'Checks for "unkonwn" or "negligible" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Unknown', 'Negligible', None]
    __lifecycle_state__ = LifecycleStates.deprecated


class FeedOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'feedoutofdate'
    __description__ = 'Fires if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days)'
    __lifecycle_state__ = LifecycleStates.deprecated
    max_age = IntegerStringParameter(name='maxage', description='Fire the trigger if the last sync was more than this number of days ago', is_required=True)

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
                        self._fire(msg="FEEDOUTOFDATE The vulnerability feed for this image distro is older than MAXAGE ("+str(self.max_age.value())+") days")
                else:
                    self._fire(
                        msg="FEEDOUTOFDATE The vulnerability feed for this image distro is older than MAXAGE (" + str(self.max_age.value()) + ") days")
            except Exception as err:
                self._fire(msg="FEEDOUTOFDATE Cannot perform data feed up-to-date check - message from server: " + str(err))


class UnsupportedDistroTrigger(BaseTrigger):
    __trigger_name__ = 'unsupporteddistro'
    __description__ = 'Fires if a vulnerability scan cannot be run against the image due to lack of vulnerability feed data for the images distro'
    __lifecycle_state__ = LifecycleStates.deprecated

    def evaluate(self, image_obj, context):
        if not have_vulnerabilities_for(DistroNamespace.for_obj(image_obj)):
            self._fire(msg="UNSUPPORTEDDISTRO cannot perform CVE scan: "+str(image_obj.distro_namespace))


class AnchoreSecGate(Gate):
    __gate_name__ = 'anchoresec'
    __description__ = 'Vulnerability checks against distro packages'
    __lifecycle_state__ = LifecycleStates.deprecated
    __superceded_by__ = 'vulnerabilities'

    __triggers__ = [
        LowSeverityTrigger,
        MediumSeverityTrigger,
        HighSeverityTrigger,
        CriticalSeverityTrigger,
        UnknownSeverityTrigger,
        FeedOutOfDateTrigger,
        UnsupportedDistroTrigger
    ]

    def prepare_context(self, image_obj, context):
        """

        :rtype:
        """
        # Load the vulnerability info up front
        context.data['loaded_vulnerabilities'] = image_obj.vulnerabilities()
        return context
