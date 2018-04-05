import calendar
import time

from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.db import DistroNamespace
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.policy.params import BooleanStringParameter, IntegerStringParameter, EnumCommaDelimStringListParameter, EnumStringParameter
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

    package_type = EnumStringParameter(name='package_type', example_str='all', enum_values=['os', 'all'], description='Only trigger for specific package type.', is_required=True, sort_order=1)
    severity_comparison = EnumStringParameter(name='severity_comparison', example_str='>', description='The type of comparison to perform for severity evaluation.', enum_values=SEVERITY_COMPARISONS.keys(), is_required=True, sort_order=2)
    severity = EnumStringParameter(name='severity', example_str='high', description='Severity to compare against', enum_values=SEVERITY_ORDERING, is_required=True, sort_order=3)
    fix_available = BooleanStringParameter(name='fix_available', example_str='true', description='If present, the fix availability for the vulnerability record must match the value of this parameter.', is_required=False, sort_order=4)

    def evaluate(self, image_obj, context):
        vulns = context.data.get('loaded_vulnerabilities')
        if not vulns:
            return

        is_fix_available = self.fix_available.value()
        comparison_idx = SEVERITY_ORDERING.index(self.severity.value().lower())
        comparison_fn = self.SEVERITY_COMPARISONS.get(self.severity_comparison.value())

        if not comparison_fn:
            raise KeyError(self.severity_comparison)

        for pkg_vuln in vulns:
            # Filter by level first
            found_severity_idx = SEVERITY_ORDERING.index(pkg_vuln.vulnerability.severity.lower()) if pkg_vuln.vulnerability.severity else 0

            if comparison_fn(found_severity_idx, comparison_idx):
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
    __description__ = "Triggers if vulnerability data is unavailable for the image's distro"

    def evaluate(self, image_obj, context):
        if not have_vulnerabilities_for(DistroNamespace.for_obj(image_obj)):
            self._fire(msg="Feed data unavailable, cannot perform CVE scan for distro: "+str(image_obj.distro_namespace))


class VulnerabilitiesGate(Gate):
    __gate_name__ = 'vulnerabilities'
    __description__ = 'CVE/Vulnerability checks'
    __triggers__ = [
        VulnerabilityMatchTrigger,
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
