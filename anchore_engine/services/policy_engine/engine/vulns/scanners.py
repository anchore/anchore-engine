"""
Scanners are responsible for finding vulnerabilities in an image.
A scanner may use persistence context or an external tool to match image content with vulnerability data and return those matches
"""
import datetime
import json
import os
from typing import Dict, List, Tuple, Union

from sqlalchemy.orm.session import Session

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common import nonos_package_types
from anchore_engine.common.models.policy_engine import (
    ImageVulnerabilitiesReport,
    VulnerabilitiesReportMetadata,
    VulnerabilityScanProblem,
)
from anchore_engine.configuration import localconfig
from anchore_engine.db.entities.policy_engine import (
    CpeV2Vulnerability,
    Image,
    ImageCpe,
    ImagePackageVulnerability,
    NvdV2Metadata,
)
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
    GrypeDBSyncManager,
    NoActiveDBSyncError,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import timer

from .cpe_matchers import DistroEnabledCpeMatcher, NonOSCpeMatcher
from .dedup import get_image_vulnerabilities_deduper
from .mappers import grype_to_engine_image_vulnerabilities, image_content_to_grype_sbom

# debug option for saving image sbom, defaults to not saving
SAVE_SBOM_TO_FILE = (
    os.getenv("ANCHORE_POLICY_ENGINE_SAVE_SBOM_TO_FILE", "false").lower() == "true"
)

# Distros that only add a CVE record to their secdb entries when a fix is available
nvd_distro_matching_enabled = (
    os.getenv("ANCHORE_ENABLE_DISTRO_NVD_MATCHES", "true").lower() == "true"
)

FIX_ONLY_DISTROS = ["alpine"]


def is_fix_only_distro(distro_name: str) -> bool:
    """
    Does the given distro's security feed/db support vulnerability records before a fix is available?

    :param distro_name:
    :return: bool
    """
    return distro_name in FIX_ONLY_DISTROS


class LegacyScanner:
    """
    Scanner wrapping the legacy vulnerabilities subsystem.
    """

    def flush_and_recompute_vulnerabilities(
        self, image_obj: Image, db_session: Session
    ) -> List[ImagePackageVulnerability]:
        """
        Wrapper for rescan_image function.
        """
        return vulnerabilities.rescan_image(image_obj, db_session)

    def get_vulnerabilities(self, image: Image) -> List[ImagePackageVulnerability]:
        distro_matches = image.vulnerabilities()
        return distro_matches

    def get_cpe_vulnerabilities(
        self,
        image: Image,
        nvd_cls: type = NvdV2Metadata,
        cpe_cls: type = CpeV2Vulnerability,
    ):
        if nvd_distro_matching_enabled and is_fix_only_distro(image.distro_name):
            matcher = DistroEnabledCpeMatcher(nvd_cls, cpe_cls)
        else:
            matcher = NonOSCpeMatcher(nvd_cls, cpe_cls)

        with timer("Image vulnerability cpe lookups", log_level="debug"):
            matches = matcher.image_cpe_vulnerabilities(image)

        return matches


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

    def _get_image_content(self, image: Image) -> Dict:
        """
        Produces image content map where the key is either 'os' or one of the non-os package types, values are lists of packages

        Example output
        {
          "java": [
            {
              "cpes": [
                "cpe:2.3:a:twilio:TwilioNotifier:0.2.1:*:*:*:*:java:*:*"
              ],
              "implementation-version": "0.2.1",
              "location": "/TwilioNotifier.hpi",
              "maven-version": "0.2.1",
              "origin": "com.twilio.jenkins",
              "package": "TwilioNotifier",
              "specification-version": "N/A",
              "type": "JAVA-HPI",
              "version": "0.2.1"
            }
          ],
          "os": [
            {
              "cpes": [
                "cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r8:*:*:*:*:*:*:*"
              ],
              "license": "GPL-2.0-only",
              "licenses": [
                "GPL-2.0-only"
              ],
              "origin": "Natanael Copa <ncopa@alpinelinux.org>",
              "package": "alpine-baselayout",
              "size": "409600",
              "sourcepkg": "alpine-baselayout",
              "type": "APKG",
              "version": "3.2.0-r8"
            }
          ]
        }
        """
        all_content = {}
        catalog_client = internal_client_for(CatalogClient, userId=image.user_id)

        # for now supported content types are os and non-os packages
        supported_content_types = ["os"] + list(nonos_package_types)

        logger.debug(
            "Fetching %s content for %s from catalog",
            supported_content_types,
            image.digest,
        )

        # fetch image content from catalog for now. preferred approach is provide image content as the input to vuln matcher
        all_content = catalog_client.get_image_content_multiple_types(
            image_digest=image.digest,
            content_types=supported_content_types,
            allow_analyzing_state=True,
        )

        return all_content

    def _get_report_generated_by(self, grype_response):
        generated_by = {"scanner": self.__class__.__name__}

        try:
            descriptor_dict = grype_response.get("descriptor", {})
            db_dict = descriptor_dict.get("db", {})
            generated_by.update(
                {
                    "grype_version": descriptor_dict.get("version"),
                    "db_checksum": db_dict.get("checksum"),
                    "db_schema_version": db_dict.get("schemaVersion"),
                    "db_built_at": db_dict.get("built"),
                }
            )
        except (AttributeError, ValueError):
            logger.exception(
                "Ignoring error parsing report metadata from grype response"
            )

        return generated_by

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
                schema_version="1.0",
                generated_at=datetime.datetime.utcnow(),
                generated_by={"scanner": self.__class__.__name__},
            ),
            problems=[],
        )

        # check and run grype sync if necessary
        try:
            GrypeDBSyncManager.run_grypedb_sync(db_session)
        except NoActiveDBSyncError:
            logger.exception("Failed to initialize local vulnerability database")
            report.problems.append(
                VulnerabilityScanProblem(
                    details="No vulnerability database found in the system. Retry after a feed sync completes setting up the vulnerability database"
                )
            )
            return report

        # create the image sbom
        try:
            sbom = image_content_to_grype_sbom(image, self._get_image_content(image))
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
            results = grype_to_engine_image_vulnerabilities(grype_response)
            report.results = get_image_vulnerabilities_deduper().execute(results)
            report.metadata.generated_by = self._get_report_generated_by(grype_response)
        except Exception:
            logger.exception("Failed to transform grype vulnerabilities response")
            report.problems.append(
                VulnerabilityScanProblem(
                    details="Failed to transform grype vulnerabilities response"
                )
            )
            return report

        return report

    def get_vulnerabilities(
        self, ids, affected_package, affected_package_version, namespace
    ) -> Tuple[List, List]:
        """
        Searches for grype db vulnerability and metadata records that match the ids and namespaces. Additionally queries
        and returns the metadata records of related vulnerabilities from the first query
        """
        # Query requested vulnerabilities
        vulnerabilities_result = (
            GrypeWrapperSingleton.get_instance().query_vulnerabilities(
                vuln_id=ids,
                affected_package=affected_package,
                affected_package_version=affected_package_version,
                namespace=namespace,
            )
        )

        # if no results are found, return empty lists
        if not vulnerabilities_result:
            return [], []

        # if namespace is only nvd, no additional query needed. return the results and the list of metadata records
        if self._is_only_nvd_namespace(namespace):
            return (
                vulnerabilities_result,
                [item.GrypeVulnerabilityMetadata for item in vulnerabilities_result],
            )

        # Get set of related nvd vulnerabilities
        related_nvd_vulnerabilities = set()
        nvd_namespace = None

        for raw_result in vulnerabilities_result:
            # If nvd record add it to the list to be queried
            if self._is_only_nvd_namespace(raw_result.GrypeVulnerability.namespace):
                related_nvd_vulnerabilities.add(raw_result.GrypeVulnerability.id)
                nvd_namespace = raw_result.GrypeVulnerability.namespace

            # Add any related vulnerabilities
            related_vulns = (
                raw_result.GrypeVulnerability.deserialized_related_vulnerabilities
            )
            if related_vulns:
                for related_vuln in related_vulns:
                    if self._is_only_nvd_namespace(related_vuln["Namespace"]):
                        # set nvd namespace. This allows it to be dynamic based on changes in grypedb
                        nvd_namespace = nvd_namespace or related_vuln["Namespace"]
                        related_nvd_vulnerabilities.add(related_vuln["ID"])

        if related_nvd_vulnerabilities:
            related_nvd_metadata_records = (
                GrypeWrapperSingleton.get_instance().query_vulnerability_metadata(
                    vuln_ids=related_nvd_vulnerabilities,
                    namespaces=[nvd_namespace],
                )
            )

            return vulnerabilities_result, related_nvd_metadata_records
        else:
            return vulnerabilities_result, []

    @staticmethod
    def _is_only_nvd_namespace(namespace: Union[str, list]) -> bool:
        """
        returns true or false based on if provided namespace is only nvd.
        Supports either list or string param
        """

        if isinstance(namespace, list):
            if len(namespace) > 1:
                return False
            return "nvd" in namespace[0].lower()
        elif isinstance(namespace, str):
            return "nvd" in namespace.lower()
        else:
            return False
