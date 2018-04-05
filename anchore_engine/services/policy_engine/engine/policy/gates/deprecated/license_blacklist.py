import re
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger, LifecycleStates
from anchore_engine.services.policy_engine.engine.policy.params import CommaDelimitedStringListParameter

class FullMatchTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'licfullmatch'
    __description__ = 'triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s)'

    license_blacklist = CommaDelimitedStringListParameter(name='licblacklist_fullmatch', example_str='BSD 2-Clause,GPLv3', description='List of license names to blacklist exactly')

    def evaluate(self, image_obj, context):
        fullmatchpkgs = []
        blacklist = [ x.strip() for x in self.license_blacklist.value()] if self.license_blacklist.value() else []

        for pkg, license in context.data.get('licenses', []):
            if license in blacklist:
                fullmatchpkgs.append(pkg + "(" + license + ")")

        if fullmatchpkgs:
            self._fire(msg='LICFULLMATCH Packages are installed that have blacklisted licenses: ' + ', '.join(fullmatchpkgs))


class SubstringMatchTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'licsubmatch'
    __description__ = 'triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s)'

    licenseblacklist_submatches = CommaDelimitedStringListParameter(name='licblacklist_submatch', example_str='agpl,mit', description='List of strings to do substring match for blacklist')

    def evaluate(self, image_obj, context):
        matchpkgs = []

        match_vals = [x.strip() for x in self.licenseblacklist_submatches.value()] if self.licenseblacklist_submatches.value() else []

        for pkg, license in context.data.get('licenses', []):
            for l in match_vals:
                if re.match(".*" + re.escape(l) + ".*", license):
                    matchpkgs.append(pkg + "(" + license + ")")

        if matchpkgs:
            self._fire(
                msg='LICSUBMATCH Packages are installed that have blacklisted licenses: ' + ', '.join(matchpkgs))


class LicenseBlacklistGate(Gate):
    __superceded_by__ = 'licenses'
    __lifecycle_state__ = LifecycleStates.deprecated
    __gate_name__ = 'licblacklist'
    __description__ = 'Package License Blacklists'
    __triggers__ = [
        FullMatchTrigger,
        SubstringMatchTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        Load all of the various package types and their licenses into a list for easy checks.

        :rtype:
        :param image_obj:
        :param context:
        :return:
        """
        licenses = []

        # NPM handling, convert to list of tuples with a single license
        for pkg_meta in image_obj.npms:
            for license in pkg_meta.licenses_json if pkg_meta.licenses_json else []:
                licenses.append((pkg_meta.name + "(npm)", license))

        # GEM handling, convert to a list of tuples with single license
        for pkg_meta in image_obj.gems:
            for license in pkg_meta.licenses_json if pkg_meta.licenses_json else []:
                licenses.append((pkg_meta.name + "(gem)", license))

        for pkg in image_obj.packages:
            for lic in pkg.license.split():
                licenses.append((pkg.name, lic))

        context.data['licenses'] = licenses
        return context