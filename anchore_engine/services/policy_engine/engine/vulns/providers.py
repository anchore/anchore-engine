import datetime
import hashlib
import json
import time
import uuid
from abc import ABC, abstractmethod
from typing import Dict

from sqlalchemy import asc, func, orm

from anchore_engine import version
from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db import DistroNamespace
from anchore_engine.db import (
    Image,
    ImageCpe,
    VulnDBMetadata,
    VulnDBCpe,
    get_thread_scoped_session as get_session,
    select_nvd_classes,
)
from anchore_engine.db import Vulnerability, ImagePackageVulnerability
from anchore_engine.services.policy_engine.api.models import (
    Vulnerability as VulnerabilityModel,
    VulnerabilityMatch,
    Artifact,
    ImageVulnerabilitiesReport,
    VulnerabilitiesReportMetadata,
    CvssCombined,
    FixedArtifact,
    Match,
)
from anchore_engine.services.policy_engine.engine.feeds.config import (
    get_provider_name,
    get_section_for_vulnerabilities,
    SyncConfig,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    have_vulnerabilities_for,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    merge_nvd_metadata_image_packages,
    merge_nvd_metadata,
    get_imageId_to_record,
)
from anchore_engine.subsys import logger as log
from anchore_engine.subsys import metrics
from anchore_engine.utils import timer
from .dedup import get_image_vulnerabilities_deduper, transfer_vulnerability_timestamps
from .scanners import LegacyScanner, GrypeVulnScanner
from .stores import ImageVulnerabilitiesStore, Status


class VulnerabilitiesProvider(ABC):
    """
    This is an abstraction for providing answers to any and all vulnerability related questions in the system.
    It encapsulates a scanner for finding vulnerabilities in an image and an optional cache manager to cache the resulting reports.
    In addition the provider support queries for vulnerabilities and aggregating vulnerability data across images
    """

    __scanner__ = None
    __store__ = None
    __config__name__ = None
    __default_sync_config__ = None

    def get_config_name(self) -> str:
        """
        Getter for provider's config name
        """
        return self.__config__name__

    def get_default_sync_config(self) -> Dict[str, SyncConfig]:
        """
        Returns the specific feeds and their configurations to be synced for this provider
        """
        return self.__default_sync_config__

    @abstractmethod
    def load_image(self, **kwargs):
        """
        Ingress the image and compute the vulnerability matches. To be used in the load image path to prime the matches
        """
        ...

    @abstractmethod
    def get_image_vulnerabilities_json(self, **kwargs):
        """
        Returns vulnerabilities report for the image in the json format. Use to fetch vulnerabilities for an already loaded image
        """
        ...

    @abstractmethod
    def get_image_vulnerabilities(self, **kwargs) -> ImageVulnerabilitiesReport:
        """
        Returns a vulnerabilities report for the image. Use to fetch vulnerabilities for an already loaded image
        """
        ...

    @abstractmethod
    def get_vulnerabilities(self, **kwargs):
        """
        Query the vulnerabilities database (not matched vulnerabilities) with filters
        """
        ...

    @abstractmethod
    def get_images_by_vulnerability(self, **kwargs):
        """
        Query the image set impacted by a specific vulnerability
        """
        ...


class LegacyProvider(VulnerabilitiesProvider):
    """
    The legacy provider is based on image data loaded into the policy-engine database.
    For backwards compatibility there is no cache manager
    """

    __scanner__ = LegacyScanner
    __store__ = None
    __config__name__ = "legacy"
    __default_sync_config__ = {
        "vulnerabilities": SyncConfig(
            enabled=True,
            url="https://ancho.re/v1/service/feeds",
        ),  # for backwards selective sync compatibility
        "nvdv2": SyncConfig(
            enabled=True, url="https://ancho.re/v1/service/feeds"
        ),  # for backwards selective sync compatibility
        "github": SyncConfig(enabled=False, url="https://ancho.re/v1/service/feeds"),
        "vulndb": SyncConfig(enabled=False, url="https://ancho.re/v1/service/feeds"),
        "packages": SyncConfig(enabled=False, url="https://ancho.re/v1/service/feeds"),
    }

    def load_image(self, image: Image, db_session, use_store=True):
        # initialize the scanner
        scanner = self.__scanner__()

        # flush existing matches, recompute matches and add them to session
        scanner.flush_and_recompute_vulnerabilities(image, db_session=db_session)

    def get_image_vulnerabilities_json(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ) -> json:
        return self.get_image_vulnerabilities(
            image, db_session, vendor_only, force_refresh, use_store
        ).to_json()

    def get_image_vulnerabilities(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ) -> ImageVulnerabilitiesReport:
        # select the nvd class once and be done
        _nvd_cls, _cpe_cls = select_nvd_classes(db_session)

        # initialize the scanner
        scanner = self.__scanner__()

        user_id = image.user_id
        image_id = image.id

        results = []

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
                fixed_artifact = vuln.fixed_artifact()

                # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
                if vendor_only and vuln.fix_has_no_advisory(fixed_in=fixed_artifact):
                    continue

                nvd_scores = [
                    CvssCombined.from_json(score)
                    for nvd_record in nvd_records
                    for score in nvd_record.get_cvss_scores_nvd()
                ]

                results.append(
                    VulnerabilityMatch(
                        vulnerability=VulnerabilityModel(
                            vulnerability_id=vuln.vulnerability_id,
                            description="NA",
                            severity=vuln.vulnerability.severity,
                            link=vuln.vulnerability.link,
                            feed="vulnerabilities",
                            feed_group=vuln.vulnerability.namespace_name,
                            cvss_scores_nvd=nvd_scores,
                            cvss_scores_vendor=[],
                            created_at=vuln.vulnerability.created_at,
                            last_modified=vuln.vulnerability.updated_at,
                        ),
                        artifact=Artifact(
                            name=vuln.pkg_name,
                            version=vuln.package.fullversion,
                            pkg_type=vuln.pkg_type,
                            pkg_path=vuln.pkg_path,
                            cpe="None",
                            cpe23="None",
                        ),
                        fixes=[
                            FixedArtifact(
                                version=str(vuln.fixed_in(fixed_in=fixed_artifact)),
                                wont_fix=vuln.fix_has_no_advisory(
                                    fixed_in=fixed_artifact
                                ),
                                observed_at=fixed_artifact.fix_observed_at
                                if fixed_artifact
                                else None,
                            )
                        ],
                        match=Match(detected_at=vuln.created_at),
                    )
                )

        # TODO move dedup here so api doesn't have to
        # cpe_vuln_listing = []
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

                    nvd_scores = [
                        CvssCombined.from_json(score)
                        for score in vulnerability_cpe.parent.get_cvss_scores_nvd()
                    ]

                    vendor_scores = [
                        CvssCombined.from_json(score)
                        for score in vulnerability_cpe.parent.get_cvss_scores_vendor()
                    ]

                    results.append(
                        VulnerabilityMatch(
                            vulnerability=VulnerabilityModel(
                                vulnerability_id=vulnerability_cpe.parent.normalized_id,
                                description="NA",
                                severity=vulnerability_cpe.parent.severity,
                                link=link,
                                feed=vulnerability_cpe.feed_name,
                                feed_group=vulnerability_cpe.namespace_name,
                                cvss_scores_nvd=nvd_scores,
                                cvss_scores_vendor=vendor_scores,
                                created_at=vulnerability_cpe.parent.created_at,
                                last_modified=vulnerability_cpe.parent.updated_at,
                            ),
                            artifact=Artifact(
                                name=image_cpe.name,
                                version=image_cpe.version,
                                pkg_type=image_cpe.pkg_type,
                                pkg_path=image_cpe.pkg_path,
                                cpe=image_cpe.get_cpestring(),
                                cpe23=image_cpe.get_cpe23string(),
                            ),
                            fixes=[
                                FixedArtifact(
                                    version=item,
                                    wont_fix=False,
                                    observed_at=vulnerability_cpe.created_at,
                                )
                                for item in vulnerability_cpe.get_fixed_in()
                            ],
                            # using vulnerability created_at to indicate the match timestamp for now
                            match=Match(detected_at=vulnerability_cpe.created_at),
                        )
                    )
        except Exception as err:
            log.exception("could not fetch CPE matches")

        return ImageVulnerabilitiesReport(
            account_id=image.user_id,
            image_id=image_id,
            results=get_image_vulnerabilities_deduper().execute(results),
            metadata=VulnerabilitiesReportMetadata(
                generated_at=datetime.datetime.utcnow(),
                uuid=str(uuid.uuid4()),
                generated_by=self._get_provider_metadata(),
            ),
            problems=[],
        )

    def get_vulnerabilities(
        self, ids, package_name_filter, package_version_filter, namespace, db_session
    ):
        """
        Return vulnerability records with the matched criteria from the feed data.
        Copy pasted query_vulnerabilities() from synchronous_operations.py

        TODO use "with timer" for timing blocks
        TODO define message models use concretely objects instead of dictionaries

        :param ids: single string or list of string ids
        :param package_name_filter: string name to filter vulns by in the affected package list
        :param package_version_filter: version for corresponding package to filter by
        :param namespace: string or list of strings to filter namespaces by
        :param db_session: active db session to use
        :return: list of dicts
        """
        return_object = []

        return_el_template = {
            "id": None,
            "namespace": None,
            "severity": None,
            "link": None,
            "affected_packages": None,
            "description": None,
            "references": None,
            "nvd_data": None,
            "vendor_data": None,
        }

        # order_by ascending timestamp will result in dedup hash having only the latest information stored for return, if there are duplicate records for NVD
        (_nvd_cls, _cpe_cls) = select_nvd_classes(db_session)

        # Set the relationship loader for use with the queries
        loader = orm.selectinload

        # Always fetch any matching nvd records, even if namespace doesn't match, since they are used for the cvss data
        qry = (
            db_session.query(_nvd_cls)
            .options(loader(_nvd_cls.vulnerable_cpes))
            .filter(_nvd_cls.name.in_(ids))
            .order_by(asc(_nvd_cls.created_at))
        )

        t1 = time.time()
        nvd_vulnerabilities = qry.all()
        nvd_vulnerabilities.extend(
            db_session.query(VulnDBMetadata)
            .options(loader(VulnDBMetadata.cpes))
            .filter(VulnDBMetadata.name.in_(ids))
            .order_by(asc(VulnDBMetadata.created_at))
            .all()
        )

        log.spew("Vuln query 1 timing: {}".format(time.time() - t1))

        api_endpoint = self._get_api_endpoint()

        if not namespace or ("nvdv2:cves" in namespace):
            dedupped_return_hash = {}
            t1 = time.time()

            for vulnerability in nvd_vulnerabilities:
                link = vulnerability.link
                if not link:
                    link = "{}/query/vulnerabilities?id={}".format(
                        api_endpoint, vulnerability.name
                    )

                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el["id"] = vulnerability.name
                namespace_el["namespace"] = vulnerability.namespace_name
                namespace_el["severity"] = vulnerability.severity
                namespace_el["link"] = link
                namespace_el["affected_packages"] = []
                namespace_el["description"] = vulnerability.description
                namespace_el["references"] = vulnerability.references
                namespace_el["nvd_data"] = vulnerability.get_cvss_data_nvd()
                namespace_el["vendor_data"] = vulnerability.get_cvss_data_vendor()

                for v_pkg in vulnerability.vulnerable_cpes:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": "*",
                        }
                        namespace_el["affected_packages"].append(pkg_el)

                if not package_name_filter or (
                    package_name_filter and namespace_el["affected_packages"]
                ):
                    dedupped_return_hash[namespace_el["id"]] = namespace_el

            log.spew("Vuln merge took {}".format(time.time() - t1))

            return_object.extend(list(dedupped_return_hash.values()))

        if namespace == ["nvdv2:cves"]:
            # Skip if requested was 'nvd'
            vulnerabilities = []
        else:
            t1 = time.time()

            qry = (
                db_session.query(Vulnerability)
                .options(loader(Vulnerability.fixed_in))
                .filter(Vulnerability.id.in_(ids))
            )

            if namespace:
                if type(namespace) == str:
                    namespace = [namespace]

                qry = qry.filter(Vulnerability.namespace_name.in_(namespace))

            vulnerabilities = qry.all()

            log.spew("Vuln query 2 timing: {}".format(time.time() - t1))

        if vulnerabilities:
            log.spew("Merging nvd data into the vulns")
            t1 = time.time()
            merged_vulns = merge_nvd_metadata(
                db_session,
                vulnerabilities,
                _nvd_cls,
                _cpe_cls,
                already_loaded_nvds=nvd_vulnerabilities,
            )
            log.spew("Vuln nvd query 2 timing: {}".format(time.time() - t1))

            for entry in merged_vulns:
                vulnerability = entry[0]
                nvds = entry[1]
                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el["id"] = vulnerability.id
                namespace_el["namespace"] = vulnerability.namespace_name
                namespace_el["severity"] = vulnerability.severity
                namespace_el["link"] = vulnerability.link
                namespace_el["affected_packages"] = []

                namespace_el["nvd_data"] = []
                namespace_el["vendor_data"] = []

                for nvd_record in nvds:
                    namespace_el["nvd_data"].extend(nvd_record.get_cvss_data_nvd())

                for v_pkg in vulnerability.fixed_in:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": v_pkg.version_format,
                        }
                        if not v_pkg.version or v_pkg.version.lower() == "none":
                            pkg_el["version"] = "*"

                        namespace_el["affected_packages"].append(pkg_el)

                for v_pkg in vulnerability.vulnerable_in:
                    if (
                        not package_name_filter or package_name_filter == v_pkg.name
                    ) and (
                        not package_version_filter
                        or package_version_filter == v_pkg.version
                    ):
                        pkg_el = {
                            "name": v_pkg.name,
                            "version": v_pkg.version,
                            "type": v_pkg.version_format,
                        }
                        if not v_pkg.version or v_pkg.version.lower() == "none":
                            pkg_el["version"] = "*"

                        namespace_el["affected_packages"].append(pkg_el)

                if not package_name_filter or (
                    package_name_filter and namespace_el["affected_packages"]
                ):
                    return_object.append(namespace_el)

        return return_object

    def get_images_by_vulnerability(
        self,
        user_id,
        id,
        severity_filter,
        namespace_filter,
        affected_package_filter,
        vendor_only,
        db_session,
    ):
        """
        Return image with nested package records that match the filter criteria

        Copy pasted query_images_by_vulnerability() from synchronous_operations.py

        TODO use "with timer" for timing blocks
        TODO define message models use concretely objects instead of dictionaries
        """

        ret_hash = {}
        pkg_hash = {}
        advisory_cache = {}

        start = time.time()
        image_package_matches = []
        image_cpe_matches = []
        image_cpe_vlndb_matches = []

        (_nvd_cls, _cpe_cls) = select_nvd_classes(db_session)

        ipm_query = (
            db_session.query(ImagePackageVulnerability)
            .filter(ImagePackageVulnerability.vulnerability_id == id)
            .filter(ImagePackageVulnerability.pkg_user_id == user_id)
        )
        icm_query = (
            db_session.query(ImageCpe, _cpe_cls)
            .filter(_cpe_cls.vulnerability_id == id)
            .filter(func.lower(ImageCpe.name) == _cpe_cls.name)
            .filter(ImageCpe.image_user_id == user_id)
            .filter(ImageCpe.version == _cpe_cls.version)
        )
        icm_vulndb_query = db_session.query(ImageCpe, VulnDBCpe).filter(
            VulnDBCpe.vulnerability_id == id,
            func.lower(ImageCpe.name) == VulnDBCpe.name,
            ImageCpe.image_user_id == user_id,
            ImageCpe.version == VulnDBCpe.version,
            VulnDBCpe.is_affected.is_(True),
        )

        if severity_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.vulnerability.has(severity=severity_filter)
            )
            icm_query = icm_query.filter(
                _cpe_cls.parent.has(severity=severity_filter)
            )  # might be slower than join
            icm_vulndb_query = icm_vulndb_query.filter(
                _cpe_cls.parent.has(severity=severity_filter)
            )  # might be slower than join
        if namespace_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.vulnerability_namespace_name
                == namespace_filter
            )
            icm_query = icm_query.filter(_cpe_cls.namespace_name == namespace_filter)
            icm_vulndb_query = icm_vulndb_query.filter(
                VulnDBCpe.namespace_name == namespace_filter
            )
        if affected_package_filter:
            ipm_query = ipm_query.filter(
                ImagePackageVulnerability.pkg_name == affected_package_filter
            )
            icm_query = icm_query.filter(
                func.lower(ImageCpe.name) == func.lower(affected_package_filter)
            )
            icm_vulndb_query = icm_vulndb_query.filter(
                func.lower(ImageCpe.name) == func.lower(affected_package_filter)
            )

        image_package_matches = ipm_query  # .all()
        image_cpe_matches = icm_query  # .all()
        image_cpe_vlndb_matches = icm_vulndb_query

        log.debug("QUERY TIME: {}".format(time.time() - start))

        start = time.time()
        if image_package_matches or image_cpe_matches or image_cpe_vlndb_matches:
            imageId_to_record = get_imageId_to_record(user_id, dbsession=db_session)

            start = time.time()
            for image in image_package_matches:
                if vendor_only and self._check_no_advisory(image, advisory_cache):
                    continue

                imageId = image.pkg_image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {
                        "image": imageId_to_record.get(imageId, {}),
                        "vulnerable_packages": [],
                    }
                    pkg_hash[imageId] = {}

                pkg_el = {
                    "name": image.pkg_name,
                    "version": image.pkg_version,
                    "type": image.pkg_type,
                    "namespace": image.vulnerability_namespace_name,
                    "severity": image.vulnerability.severity,
                }

                ret_hash[imageId]["vulnerable_packages"].append(pkg_el)
            log.debug("IMAGEOSPKG TIME: {}".format(time.time() - start))

            for cpe_matches in [image_cpe_matches, image_cpe_vlndb_matches]:
                start = time.time()
                for image_cpe, vulnerability_cpe in cpe_matches:
                    imageId = image_cpe.image_id
                    if imageId not in ret_hash:
                        ret_hash[imageId] = {
                            "image": imageId_to_record.get(imageId, {}),
                            "vulnerable_packages": [],
                        }
                        pkg_hash[imageId] = {}
                    pkg_el = {
                        "name": image_cpe.name,
                        "version": image_cpe.version,
                        "type": image_cpe.pkg_type,
                        "namespace": "{}".format(vulnerability_cpe.namespace_name),
                        "severity": "{}".format(vulnerability_cpe.parent.severity),
                    }
                    phash = hashlib.sha256(
                        json.dumps(pkg_el).encode("utf-8")
                    ).hexdigest()
                    if not pkg_hash[imageId].get(phash, False):
                        ret_hash[imageId]["vulnerable_packages"].append(pkg_el)
                    pkg_hash[imageId][phash] = True

                log.debug("IMAGECPEPKG TIME: {}".format(time.time() - start))

        start = time.time()
        vulnerable_images = list(ret_hash.values())
        return_object = {"vulnerable_images": vulnerable_images}
        log.debug("RESP TIME: {}".format(time.time() - start))

        return return_object

    def _get_provider_metadata(self):
        return {
            "name": self.get_config_name(),
            "version": version.version,
            "database_version": version.db_version,
        }

    @staticmethod
    def _check_no_advisory(img_pkg_vuln, advisory_cache):
        """
        Caches and returns vendor advisory or "won't fix" for a vulnerability.
        Cache is a dictionary with ImagePackageVulnerability hash mapped to "won't fix"

        Copied check_no_advisory() from synchronous_operations.py
        """
        phash = hashlib.sha256(
            json.dumps(
                [
                    img_pkg_vuln.pkg_name,
                    img_pkg_vuln.pkg_version,
                    img_pkg_vuln.vulnerability_namespace_name,
                ]
            ).encode("utf-8")
        ).hexdigest()
        if phash not in advisory_cache:
            advisory_cache[phash] = img_pkg_vuln.fix_has_no_advisory()

        return advisory_cache.get(phash)

    @staticmethod
    def _get_api_endpoint():
        """
        Utility function for fetching the url to external api
        """
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
    __store__ = ImageVulnerabilitiesStore
    __config__name__ = "grype"
    __default_sync_config__ = {
        "grypedb": SyncConfig(
            enabled=True,
            url="https://toolbox-data.anchore.io/grype/databases/listing.json",
        ),
        "packages": SyncConfig(enabled=False, url="https://ancho.re/v1/service/feeds"),
    }

    def load_image(self, image: Image, db_session, use_store=True):
        return self._create_new_report(image, db_session, use_store)

    def get_image_vulnerabilities_json(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ):
        if force_refresh:
            return self._create_new_report(image, db_session, use_store)
        else:
            report = self._try_load_report_from_store(image, db_session, use_store)

            if isinstance(report, ImageVulnerabilitiesReport):
                return report.to_json()
            else:
                return report

    def get_image_vulnerabilities(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ) -> ImageVulnerabilitiesReport:
        if force_refresh:
            return self._create_new_report(image, db_session, use_store)
        else:
            report = self._try_load_report_from_store(image, db_session, use_store)
            if isinstance(report, ImageVulnerabilitiesReport):
                return report
            else:
                report = ImageVulnerabilitiesReport.from_json(report)
                return report

    def _create_new_report(
        self, image: Image, db_session, use_store: bool = True
    ) -> ImageVulnerabilitiesReport:
        """
        Generates a new vulnerability report using the scanner. Flushes the cache and any existing reports for the image.
        Does NOT merge state with previously generated reports
        """

        new_report = self.__scanner__().scan_image_for_vulnerabilities(
            image, db_session
        )

        # save step only if there were no problems in report generation
        if new_report and not new_report.problems and use_store:
            # Don't let the save block results, at worst the report will be regenerated the next time
            try:
                store_manager = self.__store__(image)
                store_manager.save(new_report)
            except Exception:
                log.exception("Ignoring error saving vulnerabilities report to store")

        return new_report

    def _try_load_report_from_store(
        self,
        image: Image,
        db_session,
        use_store: bool = True,
    ):
        """
        Tries to load the report from the store if one is available and returns it if it's valid.
        If the existing report in the store has expired, creates a new report and transfers some state from the old into new
        """

        user_id = image.user_id
        image_id = image.id
        store_manager = None
        existing_report = None

        if use_store:
            try:
                store_manager = self.__store__(image)
            except:
                log.exception("Ignoring error initializing store for vulnerabilities")
                store_manager = None

        if store_manager:
            timer2 = time.time()
            try:
                existing_report, report_status = store_manager.fetch()
                if existing_report and report_status and report_status == Status.valid:
                    metrics.counter_inc(name="anchore_vulnerabilities_cache_hits")
                    metrics.histogram_observe(
                        "anchore_vulnerabilities_cache_access_latency",
                        time.time() - timer2,
                        status="hit",
                    )
                    log.info(
                        "Vulnerabilities cache hit, returning cached report for %s/%s",
                        user_id,
                        image_id,
                    )
                    return existing_report
                else:
                    metrics.counter_inc(name="anchore_vulnerabilities_cache_misses")
                    metrics.histogram_observe(
                        "anchore_vulnerabilities_cache_access_latency",
                        time.time() - timer2,
                        status="miss",
                    )
                    log.info(
                        "Vulnerabilities not cached or invalid, executing report for %s/%s",
                        user_id,
                        image_id,
                    )
            except Exception:
                log.exception(
                    "Unexpected error with vulnerabilities store. Skipping use of cache."
                )
        else:
            log.info(
                "Vulnerabilities store disabled or cannot be initialized. Generating a new report"
            )

        # if control gets here, new report has to be generated
        new_report = self.__scanner__().scan_image_for_vulnerabilities(
            image, db_session
        )

        # merge and save steps only if there were no problems
        if new_report and not new_report.problems:

            # transfer timestamps of previously found vulnerabilities
            if existing_report:
                log.debug(
                    "Attempting to transfer timestamps from existing to the new vulnerabilities report for %s/%s",
                    user_id,
                    image_id,
                )
                try:
                    existing_report = ImageVulnerabilitiesReport.from_json(
                        existing_report
                    )
                    merged_results = transfer_vulnerability_timestamps(
                        source=existing_report.results, destination=new_report.results
                    )
                    new_report.results = merged_results
                except Exception:
                    log.exception(
                        "Ignoring error reconciling timestamps from an existing vulnerability report"
                    )

            # Don't let the save block results, at worst the report will be regenerated the next time
            if store_manager:
                try:
                    store_manager.save(new_report)
                except Exception:
                    log.exception(
                        "Ignoring error saving vulnerabilities report to store"
                    )

        return new_report

    def get_vulnerabilities(self, **kwargs):
        pass

    def get_images_by_vulnerability(self, **kwargs):
        pass


# Override this map for associating different provider classes
PROVIDER_CLASSES = [LegacyProvider, GrypeProvider]
PROVIDER = None


def set_provider():
    # doesn't have to be a singleton strictly and hence getting away with globals
    global PROVIDER

    provider_name = get_provider_name(get_section_for_vulnerabilities())
    provider_class = next(
        (item for item in PROVIDER_CLASSES if item.__config__name__ == provider_name),
        None,
    )

    if not provider_class:
        log.warn(
            "No implementation found for configured provider %s. Falling back to default",
            provider_name,
        )
        provider_class = LegacyProvider

    PROVIDER = provider_class()


def get_vulnerabilities_provider():
    if not PROVIDER:
        set_provider()

    return PROVIDER
