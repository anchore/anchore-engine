import datetime
import json
import time

from anchore_engine.apis.context import ApiRequestContextProxy
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
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    merge_nvd_metadata_image_packages,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import rescan_image
from anchore_engine.subsys import logger as log
from anchore_engine.subsys import metrics
from anchore_engine.utils import timer
from anchore_engine.services.policy_engine.engine.vulns.cache_managers import (
    LegacyCacheManager,
    GrypeCacheManager,
)
from anchore_engine.services.policy_engine.engine.vulns.scanners import (
    DefaultVulnScanner,
    GrypeVulnScanner,
)

# API models

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

    __scanner__ = None
    __cache_manager__ = None

    def get_report_for_image(
        self,
        image: Image,
        vendor_only: bool,
        db_session,
        force_refresh: bool = False,
        cache: bool = True,
    ):
        user_id = image.user_id
        image_id = image.id
        cache_mgr = None

        if cache:
            try:
                cache_mgr = self.init_cache_manager(image)
            except:
                log.exception(
                    "Could not initialize cache manager for vulnerabilities, skipping cache usage"
                )
                cache_mgr = None

        if cache:
            try:
                cache_mgr = self.init_cache_manager(image)
            except:
                log.exception(
                    "Could not initialize cache manager for vulnerabilities, skipping cache usage"
                )
                cache_mgr = None

        if force_refresh:
            log.info(
                "Forcing refresh of vulnerabilities for {}/{}".format(user_id, image_id)
            )

            report = self._generate_new_report(
                image, vendor_only, force_refresh, db_session
            )
        else:
            if cache_mgr:
                timer2 = time.time()
                try:
                    cached_result = cache_mgr.refresh()
                    if cached_result:
                        metrics.counter_inc(name="anchore_vulnerabilities_cache_hits")
                        metrics.histogram_observe(
                            "anchore_vulnerabilities_cache_access_latency",
                            time.time() - timer2,
                            status="hit",
                        )
                        log.info(
                            "Returning cached result of vulnerabilities for {}/{}. Report created at: {}".format(
                                user_id,
                                image_id,
                                cached_result.get("created_at"),  # TODO fix this
                            )
                        )
                        return cached_result
                    else:
                        metrics.counter_inc(name="anchore_vulnerabilities_cache_misses")
                        metrics.histogram_observe(
                            "anchore_vulnerabilities_cache_access_latency",
                            time.time() - timer2,
                            status="miss",
                        )
                        log.info(
                            "Vulnerabilities not cached, or invalid, executing report for {}/{}".format(
                                user_id,
                                image_id,
                            )
                        )
                except Exception as ex:
                    log.exception(
                        "Unexpected error operating on vulnerabilities cache. Skipping use of cache."
                    )
            else:
                log.info(
                    "Vulnerabilities report cache disabled or cannot be initialized. Generating a new report"
                )

            # if control gets here, new report has to be generated
            report = self._generate_new_report(
                image, vendor_only, force_refresh, db_session
            )

        # Never let the cache block returning results
        try:
            if cache_mgr:
                cache_mgr.save(report)
        except Exception:
            log.exception(
                "Failed saving vulnerabilities to cache. Skipping and continuing."
            )

        return report

    def _generate_new_report(
        self, image: Image, vendor_only, force_refresh, db_session
    ):
        raise NotImplementedError()

    def init_cache_manager(self, img: Image):
        try:
            conn_timeout = ApiRequestContextProxy.get_service().configuration.get(
                "catalog_client_conn_timeout",
                DEFAULT_CACHE_CONN_TIMEOUT,
            )
            read_timeout = ApiRequestContextProxy.get_service().configuration.get(
                "catalog_client_read_timeout",
                DEFAULT_CACHE_READ_TIMEOUT,
            )
            cache_mgr = self.__cache_manager__(img, conn_timeout, read_timeout)
        except ValueError:
            log.exception("Could not leverage cache due to error")
            cache_mgr = None

        return cache_mgr


class LegacyProvider(VulnerabilitiesProvider):

    __scanner__ = DefaultVulnScanner
    __cache_manager__ = LegacyCacheManager

    def _generate_new_report(
        self, image: Image, vendor_only, force_refresh, db_session
    ):
        user_id = image.user_id
        image_id = image.id

        if force_refresh:
            log.info(
                "Forcing refresh of vulnerabilities for {}/{}".format(user_id, image_id)
            )
            try:
                rescan_image(image, db_session=db_session)
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

        # select the nvd class once and be done
        _nvd_cls, _cpe_cls = select_nvd_classes(db_session)

        # initialize the scanner
        scanner = LegacyProvider.__scanner__(_nvd_cls, _cpe_cls)

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
                all_cpe_matches = scanner.get_cpe_vulnerabilities(image)

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
            "created_at": datetime.datetime.utcnow().isoformat(),
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


class GrypeProvider(VulnerabilitiesProvider):
    __scanner__ = GrypeVulnScanner
    __cache_manager__ = GrypeCacheManager

    def _generate_new_report(
        self, image: Image, vendor_only, force_refresh, db_session
    ):
        # initialize the scanner
        scanner = self.__scanner__()
        results = scanner.get_vulnerabilities(image)
        return self._transform_grype_output(image, results)

    def _transform_grype_output(self, image, results):
        # TODO super duper hacky to fit into existing model

        report = dict()
        rows = []  # TODO barf
        cpe_vuln_listing = []  # TODO barf
        warns = []
        matches = results.get("matches", [])

        if not isinstance(matches, list):
            return report

        for item in matches:
            vuln = item.get("vulnerability")
            vuln_id = vuln.get("id")
            link = vuln.get("links")[0]
            severity = vuln.get("severity")
            fix_ver = vuln.get("fixedInVersion")
            nvd_data = []
            vendor_data = []

            artifact = item.get("artifact")
            pkg_name = artifact.get("name")
            pkg_ver = artifact.get("version")
            pkg_type = artifact.get("type")
            pkg_path = artifact.get("locations")[0].get("path")

            search_key = item.get("matchDetails").get("searchKey")

            is_legacy = False
            if "distro" in search_key:
                is_legacy = True
                feed_name = "vulnerabilities"
                distro = search_key.get("distro")

                distro_type = distro.get("type")
                if distro_type.lower() == "redhat":
                    feed_namespace = "rhel:"
                else:
                    feed_namespace = distro_type.lower() + ":"

                distro_version = distro.get("version")
                group = distro_version.split(".", 1)[0]
                feed_namespace += group
            else:
                feed_name = "nvdv2"
                feed_namespace = "nvdv2:cves"

            if is_legacy:
                row = [
                    vuln_id,
                    severity,
                    1,
                    "{}-{}".format(pkg_name, pkg_ver),
                    fix_ver if fix_ver else "None",
                    image.id,
                    "None",
                    link,
                    pkg_type,
                    feed_name,
                    feed_namespace,
                    pkg_name,
                    pkg_path,
                    pkg_ver,
                    json.dumps({"nvd_data": nvd_data, "vendor_data": vendor_data}),
                ]
                rows.append(row)
            else:
                cpe_vuln_el = {
                    "vulnerability_id": vuln_id,
                    "severity": severity,
                    "link": link,
                    "pkg_type": pkg_type,
                    "pkg_path": pkg_path,
                    "name": pkg_name,
                    "version": pkg_ver,
                    "cpe": None,
                    "cpe23": None,
                    "feed_name": feed_name,
                    "feed_namespace": feed_namespace,
                    "nvd_data": nvd_data,
                    "vendor_data": vendor_data,
                    "fixed_in": fix_ver if fix_ver else "None",
                }
                cpe_vuln_listing.append(cpe_vuln_el)

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

        return {
            "user_id": image.user_id,
            "image_id": image.id,
            "legacy_report": vuln_listing,
            "cpe_report": cpe_vuln_listing,
            "created_at": datetime.datetime.utcnow().isoformat(),
        }


default_type = GrypeProvider


def get_vulnerabilities_provider():
    return default_type()
