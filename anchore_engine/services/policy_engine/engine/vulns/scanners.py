"""
Scanners are responsible for finding vulnerabilities in an image.
A scanner may use persistence context or an external tool to match image content with vulnerability data and return those matches
"""
import datetime
import json
import os
import uuid

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.configuration import localconfig
from anchore_engine.db.entities.policy_engine import ImageCpe, Image
from anchore_engine.common.models.policy_engine import (
    ImageVulnerabilitiesReport,
    VulnerabilitiesReportMetadata,
    VulnerabilityScanProblem,
)
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
    GrypeDBSyncManager,
    NoActiveGrypeDB,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import timer
from typing import List
from .dedup import get_image_vulnerabilities_deduper
from .mappers import EngineGrypeMapper

# debug option for saving image sbom, defaults to not saving
SAVE_SBOM_TO_FILE = (
    os.getenv("ANCHORE_POLICY_ENGINE_SAVE_SBOM_TO_FILE", "true").lower() == "true"
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


class GrypeScanner:
    """
    The scanner sits a level above the grype_wrapper. It orchestrates dependencies such as grype-db for the wrapper
    and interacts with the wrapper for all things vulnerabilities

    Scanners are typically used by a provider to serve data
    """

    def _get_image_cpes(self, image: Image, db_session) -> List[ImageCpe]:
        """
        Helper function for returning all the cpes associated with the image. Override this function to change the image cpe content
        """

        return (
            db_session.query(ImageCpe)
            .filter(
                ImageCpe.image_user_id == image.user_id,
                ImageCpe.image_id == image.id,
            )
            .all()
        )

    def _get_report_metadata(self, grype_response):
        return {
            "name": "grype",
            "version": grype_response.get("descriptor").get("version"),
        }

    def scan_image_for_vulnerabilities(
        self, image: Image, db_session
    ) -> ImageVulnerabilitiesReport:
        logger.info(
            "Scanning image %s/%s for vulnerabilities",
            image.user_id,
            image.id,
        )

        report = ImageVulnerabilitiesReport(
            account_id=image.user_id,
            image_id=image.id,
            results=[],
            metadata=VulnerabilitiesReportMetadata(
                generated_at=datetime.datetime.utcnow(),
                uuid=str(uuid.uuid4()),
                generated_by={"name": "grype"},
            ),
            problems=[],
        )

        # check and run grype sync if necessary
        try:
            GrypeDBSyncManager.run_grypedb_sync()
        except NoActiveGrypeDB:
            logger.exception("Failed to initialize local vulnerability database")
            report.problems.append(
                VulnerabilityScanProblem(
                    details="No vulnerability database found in the system. Retry after a feed sync completes setting up the vulnerability database"
                )
            )
            return report

        mapper = EngineGrypeMapper()

        # create the image sbom
        try:
            sbom = mapper.to_grype_sbom(
                image, image.packages, self._get_image_cpes(image, db_session)
            )
        except Exception:
            logger.exception(
                "Failed to create the image sbom for %s/%s", image.user_id, image.id
            )
            report.problems.append(
                VulnerabilityScanProblem(details="Failed to create the image sbom")
            )
            return report

        # submit the sbom to grype wrapper and get results
        try:
            if SAVE_SBOM_TO_FILE:
                # don't bail on errors writing to file since this is for debugging only
                try:
                    file_path = "{}/sbom_{}.json".format(
                        localconfig.get_config().get("tmp_dir", "/tmp"), image.id
                    )
                    logger.debug("Writing image sbom for %s to %s", image.id, file_path)

                    with open(file_path, "w") as fp:
                        json.dump(sbom, fp, indent=2)
                except Exception:
                    logger.exception(
                        "Ignoring error writing the image sbom to file for  %s/%s Moving on",
                        image.user_id,
                        image.id,
                    )

            # submit the image for analysis to grype
            grype_response = (
                GrypeWrapperSingleton.get_instance().get_vulnerabilities_for_sbom(
                    json.dumps(sbom)
                )
            )
        except Exception:
            logger.exception(
                "Failed to scan image sbom for vulnerabilities using grype for %s/%s",
                image.user_id,
                image.id,
            )
            report.problems.append(
                VulnerabilityScanProblem(
                    details="Failed to scan image sbom for vulnerabilities using grype"
                )
            )
            return report

        # transform grype response to engine vulnerabilities and dedup
        try:
            results = mapper.to_engine_vulnerabilities(grype_response)
            report.results = get_image_vulnerabilities_deduper().execute(results)
            report.metadata.generated_by = (
                {  # TODO do this another function and add more details
                    "name": "grype",
                    "version": grype_response.get("descriptor").get("version"),
                }
            )
        except Exception:
            logger.exception("Failed to transform grype vulnerabilities response")
            report.problems.append(
                VulnerabilityScanProblem(
                    details="Failed to transform grype vulnerabilities response"
                )
            )
            return report

        return report
