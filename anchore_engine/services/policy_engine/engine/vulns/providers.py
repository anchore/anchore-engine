import json

from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db import DistroNamespace
from anchore_engine.db import (
    Image,
    get_thread_scoped_session as get_session,
    select_nvd_classes,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    have_vulnerabilities_for,
)
from anchore_engine.db import Vulnerability, ImagePackage, ImagePackageVulnerability
from anchore_engine.services.policy_engine.engine.vulns.scanners import (
    LegacyScanner,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    merge_nvd_metadata_image_packages,
)
from anchore_engine.subsys import logger as log
from anchore_engine.utils import timer


TABLE_STYLE_HEADER_LIST = [
    "CVE_ID",
    "Severity",
    "*Total_Affected",
    "Vulnerable_Package",
    "Fix_Available",
    "Fix_Images",
    "Rebuild_Images",
    "URL",
    "Package_Type",
    "Feed",
    "Feed_Group",
    "Package_Name",
    "Package_Path",
    "Package_Version",
    "CVES",
]
# Disabled by default, can be set in config file. Seconds for connection to cache for policy evals
DEFAULT_CACHE_CONN_TIMEOUT = -1
# Disabled by default, can be set in config file. Seconds for first byte timeout for policy eval cache
DEFAULT_CACHE_READ_TIMEOUT = -1


class VulnerabilitiesProvider:
    """
    This is an abstraction for providing answers to any and all vulnerability related questions in the system.
    It encapsulates a scanner for finding vulnerabilities in an image and an optional cache manager to cache the resulting reports.
    In addition the provider support queries for vulnerabilities and aggregating vulnerability data across images
    """

    __scanner__ = None
    __cache_manager__ = None

    def load_image(self, **kwargs):
        """
        Ingress the image and compute the vulnerability matches. To be used in the load image path to prime the matches
        """
        raise NotImplementedError()

    def get_image_vulnerabilities(self, **kwargs):
        """
        Returns a vulnerabilities report for the image. To be used to fetch vulnerabilities for an already loaded image
        """
        raise NotImplementedError()

    def get_vulnerabilities(self, **kwargs):
        """
        Query the vulnerabilities database (not matched vulnerabilities) with filters
        """
        raise NotImplementedError()

    def get_images_by_vulnerability(self, **kwargs):
        """
        Query the image set impacted by a specific vulnerability
        """
        raise NotImplementedError()


class LegacyProvider(VulnerabilitiesProvider):
    """
    The legacy provider is based on image data loaded into the policy-engine database.
    For backwards compatibility there is no cache manager
    """

    __scanner__ = LegacyScanner
    __cache_manager__ = None

    def load_image(self, image: Image, db_session, cache=False):
        # initialize the scanner
        scanner = self.__scanner__()

        # flush existing matches, recompute matches and add them to session
        scanner.flush_and_recompute_vulnerabilities(image, db_session=db_session)

    def get_image_vulnerabilities(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        cache: bool = True,
    ):
        # select the nvd class once and be done
        _nvd_cls, _cpe_cls = select_nvd_classes(db_session)

        # initialize the scanner
        scanner = self.__scanner__()

        user_id = image.user_id
        image_id = image.id

        if force_refresh:
            log.info(
                "Forcing refresh of vulnerabilities for {}/{}".format(user_id, image_id)
            )
            try:
                scanner.flush_and_recompute_vulnerabilities(
                    image, db_session=db_session
                )
                db_session.commit()
            except Exception as e:
                log.exception(
                    "Error refreshing cve matches for image {}/{}".format(
                        user_id, image_id
                    )
                )
                db_session.rollback()
                return make_response_error(
                    "Error refreshing vulnerability listing for image.",
                    in_httpcode=500,
                )

            db_session = get_session()
            db_session.refresh(image)

        with timer("Image vulnerability primary lookup", log_level="debug"):
            vulns = scanner.get_vulnerabilities(image)

        # Has vulnerabilities?
        warns = []
        if not vulns:
            vulns = []
            ns = DistroNamespace.for_obj(image)
            if not have_vulnerabilities_for(ns):
                warns = [
                    "No vulnerability data available for image distro: {}".format(
                        ns.namespace_name
                    )
                ]

        rows = []
        with timer("Image vulnerability nvd metadata merge", log_level="debug"):
            vulns = merge_nvd_metadata_image_packages(
                db_session, vulns, _nvd_cls, _cpe_cls
            )

        with timer("Image vulnerability output formatting", log_level="debug"):
            for vuln, nvd_records in vulns:
                # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
                if vendor_only and vuln.fix_has_no_advisory():
                    continue

                # rennovation this for new CVSS references
                cves = ""
                nvd_list = []
                all_data = {"nvd_data": nvd_list, "vendor_data": []}

                for nvd_record in nvd_records:
                    nvd_list.extend(nvd_record.get_cvss_data_nvd())

                cves = json.dumps(all_data)

                if vuln.pkg_name != vuln.package.fullversion:
                    pkg_final = "{}-{}".format(vuln.pkg_name, vuln.package.fullversion)
                else:
                    pkg_final = vuln.pkg_name

                rows.append(
                    [
                        vuln.vulnerability_id,
                        vuln.vulnerability.severity,
                        1,
                        pkg_final,
                        str(vuln.fixed_in()),
                        vuln.pkg_image_id,
                        "None",  # Always empty this for now
                        vuln.vulnerability.link,
                        vuln.pkg_type,
                        "vulnerabilities",
                        vuln.vulnerability.namespace_name,
                        vuln.pkg_name,
                        vuln.pkg_path,
                        vuln.package.fullversion,
                        cves,
                    ]
                )

        vuln_listing = {
            "multi": {
                "url_column_index": 7,
                "result": {
                    "header": TABLE_STYLE_HEADER_LIST,
                    "rowcount": len(rows),
                    "colcount": len(TABLE_STYLE_HEADER_LIST),
                    "rows": rows,
                },
                "warns": warns,
            }
        }

        cpe_vuln_listing = []
        try:
            with timer("Image vulnerabilities cpe matches", log_level="debug"):
                all_cpe_matches = scanner.get_cpe_vulnerabilities(
                    image, _nvd_cls, _cpe_cls
                )

                if not all_cpe_matches:
                    all_cpe_matches = []

                api_endpoint = self._get_api_endpoint()

                for image_cpe, vulnerability_cpe in all_cpe_matches:
                    link = vulnerability_cpe.parent.link
                    if not link:
                        link = "{}/query/vulnerabilities?id={}".format(
                            api_endpoint, vulnerability_cpe.vulnerability_id
                        )

                    cpe_vuln_el = {
                        "vulnerability_id": vulnerability_cpe.parent.normalized_id,
                        "severity": vulnerability_cpe.parent.severity,
                        "link": link,
                        "pkg_type": image_cpe.pkg_type,
                        "pkg_path": image_cpe.pkg_path,
                        "name": image_cpe.name,
                        "version": image_cpe.version,
                        "cpe": image_cpe.get_cpestring(),
                        "cpe23": image_cpe.get_cpe23string(),
                        "feed_name": vulnerability_cpe.feed_name,
                        "feed_namespace": vulnerability_cpe.namespace_name,
                        "nvd_data": vulnerability_cpe.parent.get_cvss_data_nvd(),
                        "vendor_data": vulnerability_cpe.parent.get_cvss_data_vendor(),
                        "fixed_in": vulnerability_cpe.get_fixed_in(),
                    }
                    cpe_vuln_listing.append(cpe_vuln_el)
        except Exception as err:
            log.warn("could not fetch CPE matches - exception: " + str(err))

        return {
            "user_id": image.user_id,
            "image_id": image.id,
            "legacy_report": vuln_listing,
            "cpe_report": cpe_vuln_listing,
        }

    @staticmethod
    def _get_api_endpoint():
        try:
            return get_service_endpoint("apiext").strip("/")
        except:
            log.warn(
                "Could not find valid apiext endpoint for links so will use policy engine endpoint instead"
            )
            try:
                return get_service_endpoint("policy_engine").strip("/")
            except:
                log.warn(
                    "No policy engine endpoint found either, using default but invalid url"
                )
                return "http://<valid endpoint not found>"

    def get_vulnerabilities(self, **kwargs):
        pass

    def get_images_by_vulnerability(self, **kwargs):
        pass


default_type = LegacyProvider


def get_vulnerabilities_provider():
    return default_type()
