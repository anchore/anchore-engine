"""
Scanners are responsible for finding vulnerabilities in an image.
A scanner may use persistence context or an external tool to match image content with vulnerability data and return those matches
"""
import json

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.db.entities.policy_engine import ImageCpe
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.subsys import logger
from anchore_engine.utils import timer
from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
    GrypeDBSyncManager,
)


class LegacyScanner:
    """
    Scanner wrapping the legacy vulnerabilities subsystem.
    """

    def flush_and_recompute_vulnerabilities(self, image_obj, db_session):
        """
        Wrapper for rescan_image function.
        """
        vulnerabilities.rescan_image(image_obj, db_session)

    def compute_vulnerabilities(self, image_obj):
        """
        Wrapper for vulnerabilities_for_image function
        """

        vulnerabilities.vulnerabilities_for_image(image_obj)

    def get_vulnerabilities(self, image):
        return image.vulnerabilities()

    def get_cpe_vulnerabilities(self, image, nvd_cls: type, cpe_cls: type):
        with timer("Image vulnerability cpe lookups", log_level="debug"):
            return self.dedup_cpe_vulnerabilities(
                image.cpe_vulnerabilities(_nvd_cls=nvd_cls, _cpe_cls=cpe_cls)
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

        Business logic here is to compare vendor, name, version, update and meta fields in that order
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

        update_cmp = self.compare_fields(lhs.update, rhs.update)
        if update_cmp != 0:
            return update_cmp

        meta_cmp = self.compare_fields(lhs.meta, rhs.meta)
        if meta_cmp != 0:
            return meta_cmp

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


class GrypeVulnScanner:
    """
    The scanner sits a level above the grype_wrapper. It orchestrates dependencies such as grype-db for the wrapper
    and interacts with the wrapper for all things vulnerabilities

    Scanners are typically used by a provider to serve data They are engine-agnostic components and therefore require
    higher order functions for transforming input/output to/from underlying tool format
    """

    def get_vulnerabilities(self, image_id, sbom):

        GrypeDBSyncManager.run_grypedb_sync()

        # TODO saving sbom for debugging purposes, remove this
        file_path = "/tmp/e2g_sbom_{}".format(image_id)
        logger.info("Writing grype sbom to {}".format(image_id))
        with open(file_path, "w") as fp:
            json.dump(sbom, fp, indent=2)

        return GrypeWrapperSingleton.get_instance().get_vulnerabilities_for_sbom_file(
            file_path
        )
