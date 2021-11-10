import re

from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import (
    CommaDelimitedStringListParameter,
)


class FullMatchDenyTrigger(BaseTrigger):
    __trigger_name__ = "denylist_exact_match"
    __msg_base__ = "LICFULLMATCH Packages are installed that have denylisted licenses: "    
    __description__ = "Triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s)."
    
    license_denylist = CommaDelimitedStringListParameter(
        name="licenses",
        example_str="GPLv2+,GPL-3+,BSD-2-clause",
        description="List of license names to denylist exactly.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        fullmatchpkgs = []
        denylist = (
            [x.strip() for x in self.license_denylist.value()]
            if self.license_denylist.value()
            else []
        )

        for pkg, license in context.data.get("licenses", []):
            if license in denylist:
                fullmatchpkgs.append(pkg + "(" + license + ")")

        if fullmatchpkgs:
            self._fire(
                msg=self.__msg_base__ + ", ".join(fullmatchpkgs)
            )

# For backward compatibility only
class FullMatchTrigger(FullMatchDenyTrigger):
    __trigger_name__ = "blacklist_exact_match"
    __msg_base__ = "LICFULLMATCH Packages are installed that have blacklisted licenses: "

class SubstringMatchDenyTrigger(BaseTrigger):
    __trigger_name__ = "denylist_partial_match"
    __msg_base__ = "LICSUBMATCH Packages are installed that have denylisted licenses: "    
    __description__ = "triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s)"
    
    licensedenylist_submatches = CommaDelimitedStringListParameter(
        name="licenses",
        example_str="LGPL,BSD",
        description="List of strings to do substring match for denylist.",
        is_required=True,
    )

    def evaluate(self, image_obj, context):
        matchpkgs = []

        match_vals = (
            [x.strip() for x in self.licensedenylist_submatches.value()]
            if self.licensedenylist_submatches.value()
            else []
        )

        for pkg, license in context.data.get("licenses", []):
            for l in match_vals:
                if re.match(".*" + re.escape(l) + ".*", license):
                    matchpkgs.append(pkg + "(" + license + ")")

        if matchpkgs:
            self._fire(
                msg = self.__msg_base__ + ", ".join(matchpkgs)
            )

# For backwards compatibility only
class SubstringMatchTrigger(SubstringMatchDenyTrigger):
    __trigger_name__ = "blacklist_partial_match"
    __msg_base__ = "LICSUBMATCH Packages are installed that have blacklisted licenses: "
    
    
class LicensesGate(Gate):
    __gate_name__ = "licenses"
    __description__ = (
        "License checks against found software licenses in the container image"
    )
    __triggers__ = [FullMatchTrigger, SubstringMatchTrigger, FullMatchDenyTrigger, SubstringMatchDenyTrigger]

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
        # for pkg_meta in image_obj.npms:
        #    for license in pkg_meta.licenses_json if pkg_meta.licenses_json else []:
        #        licenses.append((pkg_meta.name + "(npm)", license))

        # GEM handling, convert to a list of tuples with single license
        # for pkg_meta in image_obj.gems:
        #    for license in pkg_meta.licenses_json if pkg_meta.licenses_json else []:
        #        licenses.append((pkg_meta.name + "(gem)", license))

        for pkg in image_obj.packages:
            for lic in pkg.license.split():
                licenses.append((pkg.name, lic))

        context.data["licenses"] = licenses
        return context
