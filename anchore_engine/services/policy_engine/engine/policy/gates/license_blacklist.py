import re
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.utils import NameVersionListValidator, CommaDelimitedStringListValidator, delim_parser, barsplit_comma_delim_parser


class FullMatchTrigger(BaseTrigger):
    __trigger_name__ = 'LICFULLMATCH'
    __description__ = 'triggers if the evaluated image has a package installed with software distributed under the specified (exact match) license(s)'
    __params__ = {
        'LICBLACKLIST_FULLMATCH': CommaDelimitedStringListValidator()
    }

    def evaluate(self, image_obj, context):
        match_vals = []
        fullmatchpkgs = []
        for match_val in delim_parser(self.eval_params.get('LICBLACKLIST_FULLMATCH', '')):
            match_vals.append(match_val)

        for pkg, license in context.data.get('licenses', []):
            if license in match_vals:
                fullmatchpkgs.append(pkg + "(" + license + ")")

        if fullmatchpkgs:
            self._fire(msg='LICFULLMATCH Packages are installed that have blacklisted licenses: ' + ', '.join(fullmatchpkgs))


class SubstringMatchTrigger(BaseTrigger):
    __trigger_name__ = 'LICSUBMATCH'
    __description__ = 'triggers if the evaluated image has a package installed with software distributed under the specified (substring match) license(s)'
    __params__ = {
        'LICBLACKLIST_SUBMATCH': CommaDelimitedStringListValidator()
    }

    def evaluate(self, image_obj, context):
        match_vals = []
        matchpkgs = []

        for match_val in delim_parser(self.eval_params.get('LICBLACKLIST_SUBMATCH', '')):
            match_vals.append(match_val)

        for pkg, license in context.data.get('licenses', []):
            for l in match_vals:
                if re.match(".*" + re.escape(l) + ".*", license):
                    matchpkgs.append(pkg + "(" + license + ")")

        if matchpkgs:
            self._fire(
                msg='LICSUBMATCH Packages are installed that have blacklisted licenses: ' + ', '.join(matchpkgs))


class LicenseBlacklistGate(Gate):
    __gate_name__ = 'LICBLACKLIST'
    __triggers__ = [
        FullMatchTrigger,
        SubstringMatchTrigger
    ]

    def prepare_context(self, image_obj, context):
        """
        Load all of the various package types and their licenses into a list for easy checks.

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