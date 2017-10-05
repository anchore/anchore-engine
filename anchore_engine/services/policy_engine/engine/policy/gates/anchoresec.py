import calendar
import time

from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.utils import IntegerValidator
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.db import DistroNamespace
from anchore_engine.services.policy_engine.engine.logs import get_logger
log = get_logger()

class CveSeverityTrigger(BaseTrigger):
    __vuln_levels__ = None

    def evaluate(self, image_obj, context):
        vulns = context.data.get('loaded_vulnerabilities')
        if not vulns:
            return

        for pkg_vuln in vulns:
            if pkg_vuln.vulnerability.severity in self.__vuln_levels__:
                message = pkg_vuln.vulnerability.severity.upper() + " Vulnerability found in package - " + \
                          pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)


class LowSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'VULNLOW'
    __description__ = 'triggers if a vulnerability of LOW severity is found, along with a named package'
    __vuln_levels__ = ['Low']


class MediumSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'VULNMEDIUM'
    __description__ = 'triggers if a vulnerability of MEDIUM severity is found, along with a named package'
    __vuln_levels__ = ['Medium']


class HighSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'VULNHIGH'
    __description__ = 'triggers if a vulnerability of HIGH severity is found, along with a named package'
    __vuln_levels__ = ['High']


class CriticalSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'VULNCRITICAL'
    __description__ = 'triggers if a vulnerability of CRITICAL severity is found, along with a named package'
    __vuln_levels__ = ['Critical']


class UnknownSeverityTrigger(CveSeverityTrigger):
    __trigger_name__ = 'VULNUNKNOWN'
    __description__ = 'triggers if a vulnerability of UNKNOWN severity is found, along with a named package'
    __vuln_levels__ = ['Unknown', 'Negligible']

    def evaluate(self, image_obj, context):
        vulns = context.data.get('loaded_vulnerabilities')
        if not vulns:
            return

        for pkg_vuln in vulns:
            # Slightly relaxed condition to handle empty and unknown severity levels.
            if pkg_vuln.vulnerability.severity in self.__vuln_levels__ or not pkg_vuln.vulnerability.severity:
                message = pkg_vuln.vulnerability.severity.upper() + " Vulnerability found in package - " + \
                          pkg_vuln.pkg_name + " (" + pkg_vuln.vulnerability_id + " - " + pkg_vuln.vulnerability.link + ")"
                self._fire(instance_id=pkg_vuln.vulnerability_id + '+' + pkg_vuln.pkg_name, msg=message)


class FeedOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'FEEDOUTOFDATE'
    __description__ = 'triggers if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days)'
    __params__ = {
        'MAXAGE': IntegerValidator(),
    }

    def evaluate(self, image_obj, context):
        feeds = DataFeeds.instance()

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

        maxage = self.eval_params.get('MAXAGE')
        if maxage:
            try:
                if oldest_update is not None:
                    oldest_update = calendar.timegm(oldest_update.timetuple())
                    mintime = time.time() - int(int(maxage) * 86400)
                    if oldest_update < mintime:
                        self._fire(msg="FEEDOUTOFDATE The vulnerability feed for this image distro is older than MAXAGE ("+str(maxage)+") days")
                else:
                    self._fire(
                        msg="FEEDOUTOFDATE The vulnerability feed for this image distro is older than MAXAGE (" + str(
                            maxage) + ") days")
            except Exception as err:
                self._fire(msg="FEEDOUTOFDATE Cannot perform data feed up-to-date check - message from server: " + str(err))


class UnsupportedDistroTrigger(BaseTrigger):
    __trigger_name__ = 'UNSUPPORTEDDISTRO'
    __description__ = 'triggers if a vulnerability scan cannot be run against the image due to lack of vulnerability feed data for the images distro'

    def evaluate(self, image_obj, context):
        if not have_vulnerabilities_for(DistroNamespace.for_obj(image_obj)):
            self._fire(msg="UNSUPPORTEDDISTRO cannot perform CVE scan: "+str(image_obj.distro_namespace))


class AnchoreSecGate(Gate):
    __gate_name__ = 'ANCHORESEC'
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
        # Load the vulnerability info up front
        context.data['loaded_vulnerabilities'] = image_obj.vulnerabilities()
        return context
