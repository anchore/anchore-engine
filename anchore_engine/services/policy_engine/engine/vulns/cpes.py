import re
import typing
from typing import List, Tuple

from anchore_engine.db.entities.policy_engine import ImageCpe, ImagePackage
from anchore_engine.common import os_package_types


def compare_fields(lhs, rhs):
    """
    Comparison function for cpe fields for ordering
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


def compare_cpes(lhs: ImageCpe, rhs: ImageCpe):
    """
    Compares the cpes based on business logic and returns -1, 0 or 1 if the lhs is lower than, equal to or greater than the rhs respectively

    Business logic here is to compare vendor, name, version, update and meta fields in that order
    """
    vendor_cmp = compare_fields(lhs.vendor, rhs.vendor)
    if vendor_cmp != 0:
        return vendor_cmp

    name_cmp = compare_fields(lhs.name, rhs.name)
    if name_cmp != 0:
        return name_cmp

    version_cmp = compare_fields(lhs.version, rhs.version)
    if version_cmp != 0:
        return version_cmp

    update_cmp = compare_fields(lhs.update, rhs.update)
    if update_cmp != 0:
        return update_cmp

    meta_cmp = compare_fields(lhs.meta, rhs.meta)
    if meta_cmp != 0:
        return meta_cmp

    # all avenues of comparison have been depleted, the two cpes are same for all practical purposes
    return 0


class FuzzyCandidateCpeGenerator:
    """
    A generator for CPEs from package metadata that generates candidates predictively
    """

    embedded_semver_regex = re.compile(r".*([0-9]+\.[0-9]+\.[0-9]+).*")

    def for_distro_package(self, package: ImagePackage) -> typing.List[ImageCpe]:
        """
        Create the cpes for a single distro package

        :param package:
        :return: list of ImageCpes for the package
        """
        cpes = []

        # Do a "-" --> "_" substitution addition so may have multiple cpe candidates for a single package
        names = {package.name, re.sub("-", "_", package.name)}
        if not package.pkg_path and package.pkg_type in os_package_types:
            pkg_path = "pkgdb"
        else:
            pkg_path = package.pkg_path

        for name in names:
            # for vendor in vendors:
            c = ImageCpe()
            c.name = name
            c.version = package.version
            c.pkg_type = package.pkg_type
            c.cpetype = "a"
            c.vendor = "*"  # vendor match anything
            c.meta = "-"
            c.update = "-"
            c.pkg_path = pkg_path
            cpes.append(c)

        return cpes

    def _fuzzy_products(self, package: ImagePackage) -> typing.List[str]:
        """
        General handler for fuzzy CPE generation
        :param package:
        :return:
        """

        products = {package.name}
        # TODO: add the generic product generation code (including nomatch exclusions here)
        return list(products)

    def _fuzzy_versions(self, package: ImagePackage) -> typing.List[str]:
        versions = {package.version}
        patt = re.match(self.embedded_semver_regex, package.version)
        if patt:
            candidate_version = patt.group(1)
            versions.add(candidate_version)

        return list(versions)


class BasicVersionCpeMatcher:
    """
    Simple matcher that only examines the product and version fields for exact matches
    """

    def matches(self, cpe_a, cpe_b) -> bool:
        return cpe_a.product == cpe_b.product and cpe_a.version == cpe_b.version


class VendorEnabledMatcher:
    """
    Extended support for vendor matching, but
    """

    def matches(self, cpe_a, cpe_b) -> bool:
        return (
            cpe_a.vendor == cpe_b.vendor
            and cpe_a.product == cpe_b.product
            and cpe_a.version == cpe_b.version
        )


def dedup_cpe_vulnerabilities(image_vuln_tuples: List[Tuple]) -> List[Tuple]:
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
            if compare_cpes(current_cpe, image_cpe) > 0:
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
