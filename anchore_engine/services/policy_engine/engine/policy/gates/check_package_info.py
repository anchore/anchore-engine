from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.utils import NameVersionListValidator, CommaDelimitedStringListValidator, barsplit_comma_delim_parser, delim_parser
from anchore_engine.db import ImagePackage
from anchore_engine.services.policy_engine.engine.util.packages import compare_package_versions
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class PkgNotPresentTrigger(BaseTrigger):
    __trigger_name__ = 'PKGNOTPRESENT'
    __description__ = 'triggers if the package(s) specified in the params are not installed in the container image.  PKGFULLMATCH param can specify an exact match (ex: "curl|7.29.0-35.el7.centos").  PKGNAMEMATCH param can specify just the package name (ex: "curl").  PKGVERSMATCH can specify a minimum version and will trigger if installed version is less than the specified minimum version (ex: zlib|0.2.8-r2)',
    __params__ = {
        'PKGFULLMATCH': NameVersionListValidator(),
        'PKGNAMEMATCH': CommaDelimitedStringListValidator(),
        'PKGVERSMATCH': NameVersionListValidator()
    }

    def evaluate(self, image_obj, context):
        fullmatch = barsplit_comma_delim_parser(self.eval_params.get('PKGFULLMATCH'))
        namematch = delim_parser(self.eval_params.get('PKGNAMEMATCH'))
        vermatch = barsplit_comma_delim_parser(self.eval_params.get('PKGVERSMATCH'))

        outlist = list()
        imageId = image_obj.id

        names = set(fullmatch.keys()).union(set(namematch)).union(set(vermatch.keys()))
        if not names:
            return

        # Filter is possible since the lazy='dynamic' is set on the packages relationship in Image.
        for img_pkg in image_obj.packages.filter(ImagePackage.name.in_(names)).all():
            if img_pkg.name in fullmatch:
                if img_pkg.fullversion != fullmatch.get(img_pkg.name):
                    # Found but not right version
                    self._fire(msg="PKGNOTPRESENT input package (" + str(img_pkg.name) + ") is present (" + str(
                            img_pkg.fullversion) + "), but not at the version specified in policy (" + str(
                            fullmatch[img_pkg.name]) + ")")
                    fullmatch.pop(img_pkg.name)  # Assume only one version of a given package name is installed
                else:
                    # Remove it from the list
                    fullmatch.pop(img_pkg.name)

            # Name match is sufficient
            if img_pkg.name in namematch:
                namematch.remove(img_pkg.name)

            if img_pkg.name in vermatch:
                if img_pkg.fullversion != vermatch[img_pkg.name]:
                    # Check if version is less than param value
                    if compare_package_versions(img_pkg.distro_namespace_meta.flavor, img_pkg.name, img_pkg.version, img_pkg.name, vermatch[img_pkg.name]) < 0:
                        self._fire(msg="PKGNOTPRESENT input package (" + str(img_pkg.name) + ") is present (" + str(
                            img_pkg.fullversion) + "), but is lower version than what is specified in policy (" + str(
                            vermatch[img_pkg.name]) + ")")

                vermatch.pop(img_pkg.name)

        # Any remaining
        for pkg, version in fullmatch.items():
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + "-" + str(version) + ") is not present in container image")

        for pkg, version in vermatch.items():
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + "-" + str(
                version) + ") is not present in container image")

        for pkg in namematch:
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + ") is not present in container image")


class PackageCheckGate(Gate):
    __gate_name__ = 'PKGCHECK'
    __triggers__ = [
        PkgNotPresentTrigger
    ]