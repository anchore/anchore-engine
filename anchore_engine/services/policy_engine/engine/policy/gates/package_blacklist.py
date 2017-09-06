from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.utils import NameVersionListValidator, CommaDelimitedStringListValidator, delim_parser, barsplit_comma_delim_parser
from anchore_engine.db import ImagePackage
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class FullMatchTrigger(BaseTrigger):
    __trigger_name__ = 'PKGFULLMATCH'
    __description__ = 'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name|vers)'
    __params__ = {
        'BLACKLIST_FULLMATCH': NameVersionListValidator()
    }

    def evaluate(self, image_obj, context):
        for pkg, vers in barsplit_comma_delim_parser(self.eval_params.get('BLACKLIST_FULLMATCH','')).items():
            try:
                matches = image_obj.packages.filter(ImagePackage.name == pkg, ImagePackage.version == vers)
                for m in matches:
                    self._fire(msg='PKGFULLMATCH Package is blacklisted: ' + m.name + "-" + m.version)
            except Exception as e:
                log.exception('Error filtering packages for full match')
                pass


class NameMatchTrigger(BaseTrigger):
    __trigger_name__ = 'PKGNAMEMATCH'
    __description__ = 'triggers if the evaluated image has a package installed that matches one in the list given as a param (package_name)'
    __params__ = {
        'BLACKLIST_NAMEMATCH': CommaDelimitedStringListValidator()
    }

    def evaluate(self, image_obj, context):
        for pval in delim_parser(self.eval_params.get('BLACKLIST_NAMEMATCH','')):
            try:
                for pkg in image_obj.packages.filter(ImagePackage.name == pval):
                    self._fire(msg='PKGNAMEMATCH Package is blacklisted: ' + pkg.name)
            except Exception as e:
                log.exception('Error searching packages for blacklisted names')
                pass


class PackageBlacklistGate(Gate):
    __gate_name__ = 'PKGBLACKLIST'
    __triggers__ = [
        FullMatchTrigger,
        NameMatchTrigger
    ]