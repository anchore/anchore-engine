"""
Module for returning vulnerability reports for images
"""
from anchore_engine.utils import timer
from collections import defaultdict
from anchore_engine.db.entities.policy_engine import ImageCpe


class DefaultVulnScanner:
    """
    Scanner object for scanning an image
    """

    def __init__(self, nvd_cls: type, cpe_cls: type):
        self.nvd_cls = nvd_cls
        self.cpe_cls = cpe_cls

    def get_vulnerabilities(self, image):
        return image.vulnerabilities()

    def get_cpe_vulnerabilities(self, image):
        with timer("Image vulnerability cpe lookups", log_level="debug"):
            return self.dedup_cpe_vulnerabilities(
                image.cpe_vulnerabilities(_nvd_cls=self.nvd_cls, _cpe_cls=self.cpe_cls)
            )

    def compare_fields(self, lhs, rhs):
        """
        Comparison function for cpe fields
        - * is considered least specific and any non-* value is considered greater
        - if both sides are non-*, comparison defaults to python lexicographic comparison for consistency
        """

        if lhs == "*":
            if rhs == "*":
                return 0
            else:
                return 1
        else:
            if rhs == "*":
                return -1
            else:
                # case where both are not *, i.e. some value. pick a way to compare them, using lexicographic comparison for now
                if rhs == lhs:
                    return 0
                elif rhs > lhs:
                    return 1
                else:
                    return -1

    def compare_cpes(self, lhs: ImageCpe, rhs: ImageCpe):
        """
        Compares the cpes based on business logic and returns -1, 0 or 1 if the lhs is lower than, equal to or greater than the rhs respectively

        Business logic here is to compare vendor, name and version fields in that order
        """
        vendor_cmp = self.compare_fields(lhs.vendor, rhs.vendor)
        if vendor_cmp != 0:
            return vendor_cmp

        name_cmp = self.compare_fields(lhs.name, rhs.name)
        if name_cmp != 0:
            return name_cmp

        version_cmp = self.compare_fields(lhs.version, rhs.version)
        if version_cmp != 0:
            return version_cmp

        # all avenues of comparison have been depleted, the two cpes are same for all practical purposes
        return 0

    def dedup_cpe_vulnerabilities(self, image_vuln_tuples):
        """
        Due to multiple cpes per package in the analysis data, the list of matched vulnerabilities may contain duplicates.
        This function filters the list and yields one record aka image vulnerability cpe tuple per vulnerability affecting a package
        """
        if not image_vuln_tuples:
            return list()

        # build a hash with vulnerability as the key mapped to a unique set of packages
        dedup_hash = dict()

        for image_cpe, vuln_cpe in image_vuln_tuples:

            # construct key that ties vulnerability and package - a unique indicator for the vulnerability affecting a package
            vuln_pkg_key = (
                vuln_cpe.vulnerability_id,
                vuln_cpe.namespace_name,
                image_cpe.pkg_path,
            )

            # check if the vulnerability was already recorded for the package
            if vuln_pkg_key in dedup_hash:
                # compare the existing cpe to the new cpe
                current_cpe = dedup_hash[vuln_pkg_key][0]
                if self.compare_cpes(current_cpe, image_cpe) > 0:
                    # if the new cpe trumps the existing one, overwrite
                    dedup_hash[vuln_pkg_key] = (image_cpe, vuln_cpe)
                else:
                    # otherwise leave the existing cpe be
                    pass
            else:
                # vulnerability was never recorded for the package, nothing to compare it against
                dedup_hash[vuln_pkg_key] = (image_cpe, vuln_cpe)

        final_results = list(dedup_hash.values())

        return final_results


scanner_type = DefaultVulnScanner


def get_scanner(nvd_cls, cpe_cls):
    """
    Return
    :param nvd_cls:
    :param cpe_cls:
    :return:
    """
    # Instantiate type defined in global config
    return scanner_type(nvd_cls, cpe_cls)
