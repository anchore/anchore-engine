from collections import namedtuple
from typing import List, Tuple

from anchore_engine.db import (
    CpeV2Vulnerability,
    DistroNamespace,
    Image,
    ImageCpe,
    ImagePackage,
    NvdV2Metadata,
    VulnDBCpe,
    Vulnerability,
    get_thread_scoped_session,
)
from anchore_engine.services.policy_engine.engine.vulns.cpes import (
    FuzzyCandidateCpeGenerator,
    dedup_cpe_vulnerabilities,
)
from anchore_engine.services.policy_engine.engine.vulns.db import CpeDBQueryManager
from anchore_engine.subsys import logger
from anchore_engine.utils import timer

# Match class to bind the image and vuln sides and ease comparisons and hashing
CpeMatch = namedtuple("CpeMatch", ["image_cpe", "vuln_cpe"])


def cve_ids_for_vuln_record(vuln: Vulnerability) -> List[str]:
    """
    Get CVE Id for vuln from alpine record

    :param vuln:
    :return: list of CVE ids associated with the vulnerability record
    """

    if vuln.id.startswith("CVE-"):
        ids = [vuln.id]
    else:
        ids = []

    # Some records have references in the metadata structure as (Amazon ALAS, for an example):
    # {"CVE": ["CVE-1", "CVE-2",...]}
    try:
        refs = vuln.additional_metadata["CVE"]
    except (KeyError, AttributeError, TypeError):
        refs = []

    ids.extend(refs)
    if len(ids) > 1:
        # Ensure no duplicates
        return list(set(ids))
    else:
        return ids


def filter_secdb_entries(
    image_distro: DistroNamespace, matches: List[str], db_manager: CpeDBQueryManager
) -> List[str]:
    """
    Execute the filtering functionality itself on the sets

    :param image_distro:
    :param matches: match list to filter
    :return: filtered match list
    """

    secdb_matched_cves = db_manager.matched_records_for_namespace(image_distro, matches)

    logger.spew("Secdb matched cves %s", secdb_matched_cves)
    unmatched = set(matches).difference(secdb_matched_cves)
    return list(unmatched)


def cpes_for_image_packages(
    packages: List[ImagePackage],
) -> List[Tuple[ImagePackage, ImageCpe]]:
    """
    Generate cpes for the packages

    :param packages:
    :return:
    """
    # If pre-Syft integration, there are no CPEs for distro packages
    cpe_generator = FuzzyCandidateCpeGenerator()

    # Capture the mapping of cpes to each distro package
    os_pkg_cpe_mappings: List[Tuple[ImagePackage, ImageCpe]] = []

    for pkg in packages:
        os_pkg_cpe_mappings.extend(
            [(pkg, cpe) for cpe in cpe_generator.for_distro_package(pkg)]
        )
    return os_pkg_cpe_mappings


def cpe_product_version_keygen(cpe) -> Tuple[str]:
    """
    Key generator that uses only product and version, expects either an ImageCpe or a CpeVuln class

    :param cpe:
    :return:
    """
    # Name is an alias for product
    try:
        return (cpe.product, cpe.version)
    except AttributeError:
        return (cpe.name, cpe.version)


def cpe_vendor_product_version_keygen(cpe) -> Tuple[str]:
    """
    Key generator that uses vendor, product, and version expects either an ImageCpe or a CpeVuln class

    :param cpe:
    :return:
    """

    # Name is an alias for product
    try:
        return (cpe.vendor, cpe.product, cpe.version)
    except AttributeError:
        return (cpe.vendor, cpe.name, cpe.version)


def map_matches_to_image(
    matched_vuln_cpes: List,
    image_cpes: List[ImageCpe],
    keygen_fn=cpe_product_version_keygen,
) -> List[CpeMatch]:
    """
    Maps the vuln matches back to the image cpe by vendor, product, version tuple

    :param matched_vuln_cpes:
    :param image_cpes:
    :return:
    """
    # Join the found cpes against the input cpes, this done after the queries to make queries faster
    image_cpe_map = {keygen_fn(cpe): cpe for cpe in image_cpes}

    return [
        CpeMatch(
            image_cpe=image_cpe_map[keygen_fn(vuln)],
            vuln_cpe=vuln,
        )
        for vuln in matched_vuln_cpes
    ]


class UnsupportedCpeTypeError(Exception):
    ...


class NonOSCpeMatcher:
    """
    A CPE matcher for images. Requires that image CPE records are loaded into the database. Works only
    on non-os package types (due to constraints on how things are loaded  in the db).

    """

    def __init__(
        self,
        nvd_cls: type = NvdV2Metadata,
        cpe_cls: type = CpeV2Vulnerability,
    ):
        self.nvd_cls = nvd_cls
        self.cpe_cls = cpe_cls
        self.db_manager = CpeDBQueryManager(get_thread_scoped_session())

    def image_cpe_vulnerabilities(self, image: Image) -> List[Tuple]:
        """
        Returns the cpe-based matches for the image's non-os packages as a list of (ImageCpe, <vuln cpe>) tuples
        where the vuln cpe may be different types depending on config

        :param image: image to scan
        :return: list of (ImageCpe, <vuln cpe>) tuples
        """

        return dedup_cpe_vulnerabilities(self._scan_image_cpes(image))

    def _scan_image_cpes(
        self,
        image: Image,
    ) -> List[Tuple]:
        """
        Similar to the vulnerabilities function, but using the cpe matches instead, basically the NVD raw data source

        :return: list of (image_cpe, cpe_vulnerability) tuples
        """

        with timer("non-os cpe matcher", log_level="debug"):
            return self.db_manager.query_image_application_vulnerabilities(
                self.cpe_cls, image
            )


class DistroEnabledCpeMatcher(NonOSCpeMatcher):
    """
    Scans distro packages for CPE-based matches
    """

    # If true, will not include matches in Cpe-Sources for with the matched CVE is also present in the distro-specific source
    exclude_distro_records = True

    def _scan_image_cpes(
        self,
        image: Image,
    ) -> List[CpeMatch]:
        """
        Return a list of (image_cpe, cpe_vuln) tuples for the image where the image_cpe may be for os or non-os package types (e.g apks as well as npms)

        :param image:
        :return:
        """

        # Get matches for non-os packages
        non_os_matches = [
            CpeMatch(image_cpe=img_cpe, vuln_cpe=vuln_cpe)
            for img_cpe, vuln_cpe in super()._scan_image_cpes(image)
        ]
        os_matches = self._scan_distro_packages_by_cpe(image)
        all_matches = non_os_matches + os_matches

        # Dedup between os and non-os? There could be name conflicts
        deduped_matches = dedup_cpe_vulnerabilities(all_matches)
        mapped = [
            CpeMatch(image_cpe=img, vuln_cpe=vuln) for img, vuln in deduped_matches
        ]
        return mapped

    def _scan_distro_packages_by_cpe(self, image: Image) -> List[CpeMatch]:

        # Match the distro packages
        with timer("os cpe matcher", log_level="debug"):
            db = get_thread_scoped_session()
            db.refresh(image)
            os_matches = self._match_distro_packages_by_cpe(image)

        return os_matches

    def _query_cpe_matches(self, image_cpes: List[ImageCpe]) -> List[CpeMatch]:
        """
        Get the CVE ids for the input list of matches

        :param db:
        :param packages:
        :return:
        """
        nvd_cpes = self.db_manager.query_nvd_cpe_matches(image_cpes, self.cpe_cls)
        vulndb_cpes = self.db_manager.query_vulndb_cpes(image_cpes)
        logger.debug(
            "Found %s nvd matches and %s vulndb matches",
            len(nvd_cpes),
            len(vulndb_cpes),
        )

        # Join the found cpes against the input cpes, this done after the queries to make queries faster
        nvd_findings = map_matches_to_image(nvd_cpes, image_cpes)
        vulndb_findings = map_matches_to_image(vulndb_cpes, image_cpes)

        return nvd_findings + vulndb_findings

    @staticmethod
    def get_cve_ids(matches: List[CpeMatch]) -> List[str]:
        cve_ids = []

        for match in matches:
            if isinstance(match.vuln_cpe, VulnDBCpe):
                cve_ids.extend(match.vuln_cpe.parent.referenced_cves)
            else:
                cve_ids.append(match.vuln_cpe.parent.name)

        return list(set(cve_ids))  # Dedup the list

    def _get_cpes_for_os_packages(
        self, packages: List[ImagePackage]
    ) -> List[Tuple[ImagePackage, ImageCpe]]:
        return cpes_for_image_packages(packages)

    def _match_distro_packages_by_cpe(self, image: Image) -> List[CpeMatch]:
        """
        Returns list of tuples of (imagecpe, vulncpe) that are matches

        :param image:
        :return: list of tuples
        """
        logger.spew(
            "scanning os packages for cpe matches id=%s digest=%s",
            image.id,
            image.digest,
        )

        os_pkg_cpe_mappings = self._get_cpes_for_os_packages(image.packages)

        logger.spew("distro cpes: %s", os_pkg_cpe_mappings)

        os_cpes = [cpe for pkg, cpe in os_pkg_cpe_mappings]
        # Get the matches
        matches = self._query_cpe_matches(os_cpes)

        logger.spew(
            "pre-filter cpe distro findings: %s",
            [(match.image_cpe, match.vuln_cpe.vulnerability_id) for match in matches],
        )

        # Filter the matches if configured to do so
        if matches and self.exclude_distro_records:
            # Remove any matches that are for a CVE ID that is represented in the vendor vuln db, regardless of match status.
            matched_cve_ids = self.get_cve_ids(matches)
            filtered_matched_cve_ids = set(
                filter_secdb_entries(
                    image.distro_namespace_obj(), matched_cve_ids, self.db_manager
                )
            )

            matches = [
                match
                for match in matches
                if match.vuln_cpe.vulnerability_id in filtered_matched_cve_ids
            ]

        logger.debug(
            "post-filter cpe distro findings: %s",
            [
                (match.image_cpe.name, match.vuln_cpe.vulnerability_id)
                for match in matches
            ],
        )

        return matches
