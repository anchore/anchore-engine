import datetime
import hashlib
import json
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from marshmallow.exceptions import ValidationError
from sqlalchemy import asc, func, orm

from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.common.helpers import make_response_error
from anchore_engine.common.models.policy_engine import Advisory, Artifact
from anchore_engine.common.models.policy_engine import (
    FeedGroupMetadata as APIFeedGroupMetadata,
)
from anchore_engine.common.models.policy_engine import FeedMetadata as APIFeedMetadata
from anchore_engine.common.models.policy_engine import (
    FixedArtifact,
    ImageVulnerabilitiesReport,
    Match,
    VulnerabilitiesReportMetadata,
)
from anchore_engine.common.models.policy_engine import (
    Vulnerability as VulnerabilityModel,
)
from anchore_engine.common.models.policy_engine import VulnerabilityMatch
from anchore_engine.db import (
    DistroNamespace,
    FeedMetadata,
    Image,
    ImageCpe,
    ImagePackageVulnerability,
)
from anchore_engine.db import ImageVulnerabilitiesReport as DBImageVulnerabilitiesReport
from anchore_engine.db import VulnDBCpe, VulnDBMetadata, Vulnerability
from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.db import select_nvd_classes, session_scope
from anchore_engine.db.db_grype_db_feed_metadata import (
    NoActiveGrypeDB,
    get_most_recent_active_grypedb,
)
from anchore_engine.services.policy_engine.engine.feeds.config import (
    SyncConfig,
    get_provider_name,
    get_section_for_vulnerabilities,
)
from anchore_engine.services.policy_engine.engine.feeds.db import (
    get_all_feeds,
    get_all_feeds_detached,
    set_feed_enabled,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    GrypeDBFeed,
    have_vulnerabilities_for,
)
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    GrypeDBSyncUtilProvider,
    LegacySyncUtilProvider,
    SyncUtilProvider,
)
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    get_imageId_to_record,
    merge_nvd_metadata,
    merge_nvd_metadata_image_packages,
)
from anchore_engine.subsys import logger, metrics
from anchore_engine.utils import timer

from .dedup import get_image_vulnerabilities_deduper, transfer_vulnerability_timestamps
from .mappers import EngineGrypeDBMapper
from .scanners import GrypeScanner, LegacyScanner
from .stores import ImageVulnerabilitiesStore, Status


class InvalidFeed(Exception):
    pass


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

    @abstractmethod
    def get_sync_utils(self, sync_configs: Dict[str, SyncConfig]) -> SyncUtilProvider:
        """
        Get a SyncUtilProvider.
        """
        ...

    @abstractmethod
    def rescan_images_loaded_during_feed_sync(
        self, uuid: str, from_time: datetime.datetime, to_time: datetime.datetime
    ):
        """
        Legacy holdout for updating vulnerability matches of images that were loaded during the feed sync
        """

    def _get_db_feeds(self) -> List[FeedMetadata]:
        """
        Returns all feeds excluding grypedb feed in detached state
        """
        feeds = get_all_feeds_detached()
        return list(
            filter(lambda feed: feed.name in self.__default_sync_config__.keys(), feeds)
        )

    def get_feeds(self) -> List[APIFeedMetadata]:
        """
        Builds the response for the get_list_feeds endpoint. Gets all feeds and their groups for the provider and returns
        them in correct json format based on models

        :return: JSON list of APIFeedMetadata and their groups converted to json
        :rtype: list
        """
        response = []

        for db_feed in self._get_db_feeds():
            response.append(self.get_feed(db_feed))

        return response

    def get_feed(self, db_feed: FeedMetadata) -> APIFeedMetadata:
        """
        Returns feed and its groups as api models
        """
        if not db_feed:
            raise ValueError(db_feed)
        self.validate_feed(db_feed.name)

        feed_meta = APIFeedMetadata(
            name=db_feed.name,
            last_full_sync=db_feed.last_full_sync,
            created_at=db_feed.created_at,
            updated_at=db_feed.last_update,
            enabled=db_feed.enabled,
            groups=[],
        )

        feed_meta.groups = self._get_feed_groups(db_feed)
        return feed_meta

    def get_feed_groups(self, db_feed: FeedMetadata) -> List[APIFeedGroupMetadata]:
        """
        Given a feed this function returns the groups for that feed as a list of APIFeedGroupMetadata

        :return: List of APIFeedGroupMetadata corresponding to feed
        :rtype: List[APIFeedGroupMetadata]
        """
        if not db_feed:
            raise ValueError(db_feed)
        self.validate_feed(db_feed.name)

        return self._get_feed_groups(db_feed)

    @abstractmethod
    def _get_feed_groups(self, db_feed: FeedMetadata) -> List[APIFeedGroupMetadata]:
        """
        Returns the groups of feed as a list of APIFeedGroupMetadata

        :return: List of feed's groups
        :rtype: List[APIFeedGroupMetadata]
        """
        ...

    @abstractmethod
    def update_feed_group_counts(self) -> None:
        """
        Update counts of feed and groups
        """
        ...

    @abstractmethod
    def is_image_vulnerabilities_updated(
        self, image: Image, db_session, since: datetime.datetime
    ):
        """
        Returns a boolean value - True if the image vulnerabilites were updated since the timestamp, False otherwise
        """
        ...

    def update_feed_enabled_status(
        self, feed_name: str, enabled: bool
    ) -> Optional[APIFeedMetadata]:
        self.validate_feed(feed_name)

        with session_scope() as session:
            feed = set_feed_enabled(session, feed_name, enabled)
            if not feed:
                return None

            return self.get_feed(feed)

    def validate_feed(self, feed_name: str) -> None:
        """
        Raises a ValueError if the feed name is not available on the provider. Does nothing if it is valid
        """
        if feed_name not in self.__default_sync_config__.keys():
            raise InvalidFeed(
                "%s feed is not supported by %s provider, supported feeds are %s",
                feed_name,
                self.__config__name__,
                list(self.__default_sync_config__.keys()),
            )

    @abstractmethod
    def delete_image_vulnerabilities(self, image: Image, db_session):
        """
        Delete image vulnerabilities maintained by the provider
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
        warns = []
        results = []

        if force_refresh:
            logger.info(
                "Forcing refresh of vulnerabilities for {}/{}".format(user_id, image_id)
            )
            try:
                scanner.flush_and_recompute_vulnerabilities(
                    image, db_session=db_session
                )
                db_session.commit()
            except Exception as e:
                logger.exception(
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
        if not vulns:
            vulns = []
            ns = DistroNamespace.for_obj(image)
            if not have_vulnerabilities_for(ns):
                warns += [
                    "No vulnerability data available for image distro: {}".format(
                        ns.namespace_name
                    )
                ]

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

                # Don't bail on errors building nvd references or advisories, should never happen with the helper functions but just in case
                try:
                    nvd_refs = [
                        nvd_record.to_nvd_reference() for nvd_record in nvd_records
                    ]
                except Exception:
                    logger.debug(
                        "Ignoring error building nvd CVSS scores for %s",
                        vuln.vulnerability_id,
                    )
                    nvd_refs = []

                advisories = []
                if fixed_artifact.fix_metadata:
                    vendor_advisories = fixed_artifact.fix_metadata.get(
                        "VendorAdvisorySummary", []
                    )
                    if vendor_advisories:
                        try:
                            advisories = [
                                Advisory.from_json(vendor_advisory_dict)
                                for vendor_advisory_dict in vendor_advisories
                            ]
                        except ValidationError:
                            logger.debug(
                                "Ignoring error building vendor advisories for %s",
                                vuln.vulnerability_id,
                            )

                fixed_in = vuln.fixed_in(fixed_in=fixed_artifact)

                results.append(
                    VulnerabilityMatch(
                        vulnerability=VulnerabilityModel(
                            vulnerability_id=vuln.vulnerability_id,
                            description=None,
                            severity=vuln.vulnerability.severity,
                            link=vuln.vulnerability.link,
                            feed="vulnerabilities",
                            feed_group=vuln.vulnerability.namespace_name,
                            cvss=[],  # backwards compatibility - distro vulns didn't used to provide cvss
                        ),
                        artifact=Artifact(
                            name=vuln.pkg_name,
                            version=vuln.package.fullversion,
                            pkg_type=vuln.pkg_type,
                            location=vuln.pkg_path,
                            cpe=None,
                            cpes=[],
                        ),
                        fix=FixedArtifact(
                            versions=[fixed_in] if fixed_in else [],
                            wont_fix=vuln.fix_has_no_advisory(fixed_in=fixed_artifact),
                            observed_at=fixed_artifact.fix_observed_at
                            if fixed_artifact
                            else None,
                            advisories=advisories,
                        ),
                        match=Match(detected_at=vuln.created_at),
                        nvd=nvd_refs,
                    )
                )

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

                    # Don't bail on errors building cvss scores, should never happen with the helper functions but just in case
                    try:
                        nvd_refs = vulnerability_cpe.parent.get_all_nvd_references()
                        cvss_objects = vulnerability_cpe.parent.get_all_cvss()
                    except Exception:
                        logger.debug(
                            "Ignoring error building nvd refs and or CVSS scores for %s",
                            vulnerability_cpe.vulnerability_id,
                        )
                        nvd_refs = []
                        cvss_objects = []

                    results.append(
                        VulnerabilityMatch(
                            vulnerability=VulnerabilityModel(
                                vulnerability_id=vulnerability_cpe.parent.normalized_id,
                                description=None,
                                severity=vulnerability_cpe.parent.severity,
                                link=link,
                                feed=vulnerability_cpe.feed_name,
                                feed_group=vulnerability_cpe.namespace_name,
                                cvss=cvss_objects,
                            ),
                            artifact=Artifact(
                                name=image_cpe.name,
                                version=image_cpe.version,
                                pkg_type=image_cpe.pkg_type,
                                location=image_cpe.pkg_path,
                                cpe=image_cpe.get_cpestring(),
                                cpes=[image_cpe.get_cpe23string()],
                            ),
                            fix=FixedArtifact(
                                versions=vulnerability_cpe.get_fixed_in(),
                                wont_fix=False,
                                observed_at=vulnerability_cpe.created_at
                                if vulnerability_cpe.get_fixed_in()
                                else None,
                                advisories=[],
                            ),
                            # using vulnerability created_at to indicate the match timestamp for now
                            match=Match(detected_at=vulnerability_cpe.created_at),
                            nvd=nvd_refs,
                        )
                    )
        except Exception as err:
            logger.exception("could not fetch CPE matches")

        return ImageVulnerabilitiesReport(
            account_id=image.user_id,
            image_id=image_id,
            results=get_image_vulnerabilities_deduper().execute(results),
            metadata=VulnerabilitiesReportMetadata(
                schema_version="1.0",
                generated_at=datetime.datetime.utcnow(),
                generated_by={
                    "scanner": self.__scanner__.__name__,
                },
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

        logger.spew("Vuln query 1 timing: {}".format(time.time() - t1))

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

            logger.spew("Vuln merge took {}".format(time.time() - t1))

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

            logger.spew("Vuln query 2 timing: {}".format(time.time() - t1))

        if vulnerabilities:
            logger.spew("Merging nvd data into the vulns")
            t1 = time.time()
            merged_vulns = merge_nvd_metadata(
                db_session,
                vulnerabilities,
                _nvd_cls,
                _cpe_cls,
                already_loaded_nvds=nvd_vulnerabilities,
            )
            logger.spew("Vuln nvd query 2 timing: {}".format(time.time() - t1))

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
        account_id,
        vulnerability_id,
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
            .filter(ImagePackageVulnerability.vulnerability_id == vulnerability_id)
            .filter(ImagePackageVulnerability.pkg_user_id == account_id)
        )
        icm_query = (
            db_session.query(ImageCpe, _cpe_cls)
            .filter(_cpe_cls.vulnerability_id == vulnerability_id)
            .filter(func.lower(ImageCpe.name) == _cpe_cls.name)
            .filter(ImageCpe.image_user_id == account_id)
            .filter(ImageCpe.version == _cpe_cls.version)
        )
        icm_vulndb_query = db_session.query(ImageCpe, VulnDBCpe).filter(
            VulnDBCpe.vulnerability_id == vulnerability_id,
            func.lower(ImageCpe.name) == VulnDBCpe.name,
            ImageCpe.image_user_id == account_id,
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

        logger.debug("QUERY TIME: {}".format(time.time() - start))

        start = time.time()
        if image_package_matches or image_cpe_matches or image_cpe_vlndb_matches:
            imageId_to_record = get_imageId_to_record(account_id, dbsession=db_session)

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
            logger.debug("IMAGEOSPKG TIME: {}".format(time.time() - start))

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

                logger.debug("IMAGECPEPKG TIME: {}".format(time.time() - start))

        start = time.time()
        vulnerable_images = list(ret_hash.values())
        return_object = {"vulnerable_images": vulnerable_images}
        logger.debug("RESP TIME: {}".format(time.time() - start))

        return return_object

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
            logger.warn(
                "Could not find valid apiext endpoint for links so will use policy engine endpoint instead"
            )
            try:
                return get_service_endpoint("policy_engine").strip("/")
            except:
                logger.warn(
                    "No policy engine endpoint found either, using default but invalid url"
                )
                return "http://<valid endpoint not found>"

    def get_sync_utils(
        self, sync_configs: Dict[str, SyncConfig]
    ) -> LegacySyncUtilProvider:
        """
        Get a SyncUtilProvider.
        """
        return LegacySyncUtilProvider(sync_configs)

    def rescan_images_loaded_during_feed_sync(
        self, uuid: str, from_time: datetime.datetime, to_time: datetime.datetime
    ):
        """
        If this was a vulnerability update (e.g. timestamps vuln feeds lies in that interval), then look for any images that were loaded in that interval and
        re-scan the cves for those to ensure that no ordering of transactions caused cves to be missed for an image.

        This is an alternative to a blocking approach by which image loading is blocked during feed syncs.

        :param uuid:
        :param from_time:
        :param to_time:
        :return: count of updated images
        """

        if from_time is None or to_time is None:
            raise ValueError("Cannot process None timestamp")

        logger.info(
            "Rescanning images loaded between {} and {} (operation_id={})".format(
                from_time.isoformat(), to_time.isoformat(), uuid
            )
        )
        count = 0

        db = get_session()
        try:
            # it is critical that these tuples are in proper index order for the primary key of the Images object so that subsequent get() operation works
            imgs = [
                (x.id, x.user_id)
                for x in db.query(Image).filter(
                    Image.created_at >= from_time, Image.created_at <= to_time
                )
            ]
            logger.info(
                "Detected images: {} for rescan (operation_id={})".format(
                    " ,".join([str(x) for x in imgs]) if imgs else "[]", uuid
                )
            )
        finally:
            db.rollback()

        retry_max = 3
        for img in imgs:
            for i in range(retry_max):
                try:
                    # New transaction for each image to get incremental progress
                    db = get_session()
                    try:
                        # If the type or ordering of 'img' tuple changes, this needs to be updated as it relies on symmetry of that tuple and the identity key of the Image entity
                        image_obj = db.query(Image).get(img)
                        if image_obj:
                            logger.info(
                                "Rescanning image {} post-vuln sync. (operation_id={})".format(
                                    img, uuid
                                )
                            )
                            self.load_image(image_obj, db_session=db)
                            count += 1
                        else:
                            logger.warn(
                                "Failed to lookup image with tuple: {} (operation_id={})".format(
                                    str(img), uuid
                                )
                            )

                        db.commit()

                    finally:
                        db.rollback()

                    break
                except Exception as e:
                    logger.exception(
                        "Caught exception updating vulnerability scan results for image {}. Waiting and retrying (operation_id={})".format(
                            img, uuid
                        )
                    )
                    time.sleep(5)

        return count

    def update_feed_group_counts(self) -> None:
        """
        Update counts of feed and groups
        """
        DataFeeds.update_counts()

    def is_image_vulnerabilities_updated(
        self, image: Image, db_session, since: datetime.datetime
    ):
        """
        Image vulnerabilities *may be* updated after feeds are synced. This function determines if the image vulnerabilities
        have been updated by comparing the last_sync timestamp of the feed groups with the input timestamp

        Copied over from EvaluationCacheManager._inputs_changed in synchronous_operations.py
        """
        # TODO: zhill - test more
        feed_group_updated_list = [
            group.last_sync
            if group.last_sync is not None
            else datetime.datetime.utcfromtimestamp(0)
            for feed in get_all_feeds(db_session)
            for group in feed.groups
        ]
        return (
            max(feed_group_updated_list) > since if feed_group_updated_list else False
        )

    def _get_feed_groups(self, db_feed: FeedMetadata) -> List[APIFeedGroupMetadata]:
        """
        Given a feed this function returns the groups for that feed as a list of APIFeedGroupMetadata

        :return: List of APIFeedGroupMetadata corresponding to feed
        :rtype: List[APIFeedGroupMetadata]
        """
        groups = []
        for group in db_feed.groups:
            groups.append(
                APIFeedGroupMetadata(
                    name=group.name,
                    last_sync=group.last_sync,
                    created_at=group.created_at,
                    updated_at=group.last_update,
                    enabled=group.enabled,
                    record_count=group.count,
                )
            )

        return groups

    def delete_image_vulnerabilities(self, image: Image, db_session):
        for pkg_vuln in image.vulnerabilities():
            db_session.delete(pkg_vuln)


class GrypeProvider(VulnerabilitiesProvider):
    __scanner__ = GrypeScanner
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
        with timer("grype provider load-image", log_level="info"):
            return self._create_new_report(image, db_session, use_store)

    def get_image_vulnerabilities_json(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ):
        with timer("grype provider get-image-vulnerabilities-json", log_level="info"):
            if force_refresh:
                report = self._create_new_report(image, db_session, use_store)
            else:
                report = self._try_load_report_from_store(image, db_session)

            if vendor_only:
                if not isinstance(report, ImageVulnerabilitiesReport):
                    report = ImageVulnerabilitiesReport.from_json(report)

                report.results = self._exclude_wont_fix(report.results)
                report = report.to_json()
            else:
                if isinstance(report, ImageVulnerabilitiesReport):
                    report = report.to_json()

            return report

    def get_image_vulnerabilities(
        self,
        image: Image,
        db_session,
        vendor_only: bool = True,
        force_refresh: bool = False,
        use_store: bool = True,
    ) -> ImageVulnerabilitiesReport:
        with timer("grype provider get-image-vulnerabilities", log_level="info"):
            if force_refresh:
                report = self._create_new_report(image, db_session, use_store)
            else:
                report = self._try_load_report_from_store(image, db_session)

            if not isinstance(report, ImageVulnerabilitiesReport):
                report = ImageVulnerabilitiesReport.from_json(report)

            if vendor_only:
                report.results = self._exclude_wont_fix(report.results)

            return report

    @staticmethod
    def _exclude_wont_fix(matches: List[VulnerabilityMatch]):
        """
        Exclude matches that are explicitly marked wont_fix = True. Includes all other matches, wont_fix = False, None or any string which should never be the case
        """
        return (
            list(
                filter(
                    lambda x: not (
                        x.fix and isinstance(x.fix.wont_fix, bool) and x.fix.wont_fix
                    ),
                    matches,
                )
            )
            if matches
            else []
        )

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
                store_manager.save(new_report, db_session)
            except Exception:
                logger.exception(
                    "Ignoring error saving vulnerabilities report to store"
                )

        return new_report

    def _try_load_report_from_store(
        self,
        image: Image,
        db_session,
    ):
        """
        Tries to load the report from the store if one is available and returns it if it's valid.
        If the existing report in the store has expired, creates a new report and transfers some state from the old into new
        """

        user_id = image.user_id
        image_id = image.id
        existing_report = None

        # initialize store manager first
        store_manager = self.__store__(image)

        timer2 = time.time()
        try:
            existing_report, report_status = store_manager.fetch(db_session)
            if existing_report and report_status and report_status == Status.valid:
                metrics.counter_inc(name="anchore_vulnerabilities_cache_hits")
                metrics.histogram_observe(
                    "anchore_vulnerabilities_cache_access_latency",
                    time.time() - timer2,
                    status="hit",
                )
                logger.info(
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
                logger.info(
                    "Vulnerabilities not cached or invalid, executing report for %s/%s",
                    user_id,
                    image_id,
                )
        except Exception:
            logger.exception(
                "Unexpected error with vulnerabilities store. Skipping use of cache."
            )

        # if control gets here, new report has to be generated
        new_report = self.__scanner__().scan_image_for_vulnerabilities(
            image, db_session
        )

        # check for problems generating the report
        if new_report and not new_report.problems:
            # merge and save steps only if there were no problems

            if existing_report:
                # transfer timestamps of previously found vulnerabilities
                logger.debug(
                    "Transfer timestamps from existing to the new vulnerabilities report for %s/%s",
                    user_id,
                    image_id,
                )
                try:
                    existing_report = ImageVulnerabilitiesReport.from_json(
                        existing_report
                    )
                    with timer("transfer timestamps from existing report"):
                        merged_results = transfer_vulnerability_timestamps(
                            source=existing_report.results,
                            destination=new_report.results,
                        )
                    new_report.results = merged_results
                except Exception:
                    logger.exception(
                        "Ignoring error reconciling timestamps from an existing vulnerability report"
                    )

            # Don't let the save block results, at worst the report will be regenerated the next time
            try:
                store_manager.save(new_report, db_session)
            except Exception:
                logger.exception(
                    "Ignoring error saving vulnerabilities report to store"
                )

            return new_report
        elif existing_report:
            # if there were problems generating the report, return the stored version if its available
            logger.warn(
                "Failed to generate new image vulnerabilities report for %s/%s. Returning the existing report",
                user_id,
                image_id,
            )

            return existing_report
        else:
            logger.warn(
                "Failed to generate new image vulnerabilities report for %s/%s",
                user_id,
                image_id,
            )

            return new_report

    def get_vulnerabilities(
        self, ids, affected_package, affected_package_version, namespace, session
    ):
        scanner = self.__scanner__()

        # Get vulnerability results from grype db, through the grype wrapper, via the scanner
        unmapped_results = scanner.get_vulnerabilities(
            ids, affected_package, affected_package_version, namespace
        )

        # Map grype db vulnerabilities into engine vulnerabilities
        mapped_results = EngineGrypeDBMapper().to_engine_vulnerabilities(
            unmapped_results
        )
        return mapped_results

    def get_images_by_vulnerability(
        self,
        account_id,
        vulnerability_id,
        severity_filter,
        namespace_filter,
        affected_package_filter,
        vendor_only,
        db_session,
    ):
        """
        Return image with nested package records that match the filter criteria.

        This is a rather slow and hacky implementation that uses a jsonb query to look up reports in the database.
        The matched reports are then loaded into the python space and additional filters are applied
        """
        # format of the JSONB column that holds the report
        #     {
        #         "type": "direct",
        #         "result": {
        #             "account_id": "admin",
        #             "image_id": "da28a15dbf563fbc5a486f622b44970ee1bf10f48013bab640f403b06b278543",
        #             "metadata": {
        #                 "generated_at": "2021-06-04T02:27:35Z",
        #                 "generated_by": {
        #                     "db_built_at": "2021-06-03T12:30:51Z",
        #                     "db_checksum": "sha256:31e09fb931256cd6dabb54092727c56b3c2a0c9016edd3f90a207f92df4d8c1c",
        #                     "db_schema_version": 3,
        #                     "grype_version": "0.13.0",
        #                     "scanner": "GrypeScanner",
        #                 },
        #                 "schema_version": "1.0",
        #             },
        #             "problems": [],
        #             "results": [
        #                 {
        #                     "artifact": {
        #                         "cpe": None,
        #                         "cpes": [],
        #                         "location": "pkgdb",
        #                         "name": "openjdk8",
        #                         "pkg_type": "APKG",
        #                         "version": "8.212.04-r0",
        #                     },
        #                     "fix": {
        #                         "advisories": [],
        #                         "observed_at": "2021-06-04T02:27:35Z",
        #                         "versions": ["8.232.09-r0"],
        #                         "wont_fix": False,
        #                     },
        #                     "match": {"detected_at": "2021-06-03T05:20:09Z"},
        #                     "nvd": [],
        #                     "vulnerability": {
        #                         "cvss": [],
        #                         "description": None,
        #                         "feed": "vulnerabilities",
        #                         "feed_group": "alpine:3.9",
        #                         "link": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-2987",
        #                         "severity": "Medium",
        #                         "vulnerability_id": "CVE-2019-2987",
        #                     },
        #                 },
        #             ],
        #         },
        #     }
        with timer("grype provider get-images-by-vulnerability", log_level="info"):
            vulnerable_images = []
            results = {"vulnerable_images": vulnerable_images}

            # construct a jsonb query for result->results->vulnerability->vulnerability_id
            db_records = (
                db_session.query(DBImageVulnerabilitiesReport)
                .filter(DBImageVulnerabilitiesReport.account_id == account_id)
                .filter(
                    DBImageVulnerabilitiesReport.result.contains(
                        {
                            "result": {
                                "results": [
                                    {
                                        "vulnerability": {
                                            "vulnerability_id": vulnerability_id
                                        }
                                    }
                                ]
                            }
                        }
                    )
                )
                .all()
            )

            logger.debug(
                "Found %d report(s) containing %s",
                len(db_records),
                vulnerability_id,
            )
            if not db_records:
                return results

            # horribly hacky utility function to get catalog owned tag history info for all images this user owns
            image_to_record = get_imageId_to_record(account_id, dbsession=db_session)

            for db_record in db_records:
                try:
                    # parse the report
                    report = ImageVulnerabilitiesReport.from_json(
                        db_record.result["result"]
                    )

                    # apply other filters now
                    filtered_dicts = self._filter_vulnerability_matches(
                        matches=report.results,
                        vulnerability_id=vulnerability_id,
                        severity_filter=severity_filter,
                        namespace_filter=namespace_filter,
                        affected_package_filter=affected_package_filter,
                        vendor_only=vendor_only,
                    )

                    # construct a return object
                    if filtered_dicts:
                        image_id = report.image_id
                        vulnerable_images.append(
                            {
                                "image": image_to_record.get(image_id, {}),
                                "vulnerable_packages": filtered_dicts,
                            }
                        )
                except:
                    logger.exception(
                        "Ignoring error processing %s/%s for images by vulnerability query",
                        account_id,
                        db_record.image_digest,
                    )

            return results

    @staticmethod
    def _filter_vulnerability_matches(
        matches: List[VulnerabilityMatch],
        vulnerability_id,
        severity_filter=None,
        namespace_filter=None,
        affected_package_filter=None,
        vendor_only=None,
    ) -> List[Dict]:
        filtered_dicts = []

        for match in matches:
            # find the result with the vulnerability id first
            if match.vulnerability.vulnerability_id == vulnerability_id:
                # now apply other the filters
                if severity_filter and severity_filter != match.vulnerability.severity:
                    continue
                if (
                    namespace_filter
                    and namespace_filter != match.vulnerability.feed_group
                ):
                    continue
                if (
                    affected_package_filter
                    and affected_package_filter != match.artifact.name
                ):
                    continue
                if (
                    isinstance(vendor_only, bool)
                    and vendor_only  # true means vendor may fix
                    and match.fix.wont_fix  # true means vendor won't fix
                ):
                    continue

                # tada! this is a match for the query

                pkg_el = {
                    "name": match.artifact.name,
                    "version": match.artifact.version,
                    "type": match.artifact.pkg_type,
                    "namespace": match.vulnerability.feed_group,
                    "severity": match.vulnerability.severity,
                }

                filtered_dicts.append(pkg_el)

        return filtered_dicts

    def get_sync_utils(
        self, sync_configs: Dict[str, SyncConfig]
    ) -> GrypeDBSyncUtilProvider:
        """
        Get a SyncUtilProvider.
        """
        return GrypeDBSyncUtilProvider(sync_configs)

    def rescan_images_loaded_during_feed_sync(
        self, uuid: str, from_time: datetime.datetime, to_time: datetime.datetime
    ):
        """
        This is a no-op for grype provider since vulnerability matches are not computed the same way as the legacy provider.
        grype-db feed sync will refresh the matches for all images in the system
        """
        pass

    def update_feed_group_counts(self) -> None:
        """
        Counts on grypedb are static so no need to update
        """
        return

    def _get_feed_groups(self, db_feed: FeedMetadata) -> List[APIFeedGroupMetadata]:
        """
        Overrides function on parent class to handle grype feed. If feed is not grype it calls the super function
        Otherwise, it builds the group response for the grype feed using the GrypeDBFeedMetadata record
        """
        groups = []

        if db_feed.name != GrypeDBFeed.__feed_name__:
            for group in db_feed.groups:
                groups.append(
                    APIFeedGroupMetadata(
                        name=group.name,
                        last_sync=group.last_sync,
                        created_at=group.created_at,
                        updated_at=group.last_update,
                        enabled=group.enabled,
                        record_count=group.count,
                    )
                )
        else:
            with session_scope() as session:
                try:
                    active_db = get_most_recent_active_grypedb(session)
                    for raw_group in active_db.groups:
                        groups.append(APIFeedGroupMetadata.from_json(raw_group))
                except NoActiveGrypeDB:
                    logger.info("No active grypedb present")
                    groups = []
        return groups

    def update_feed_group_counts(self) -> None:
        """
        Counts on grypedb are static so no need to update
        """
        return

    def is_image_vulnerabilities_updated(
        self, image: Image, db_session, since: datetime.datetime
    ):
        """
        This function determines if the image vulnerabilities were updated based on the state of the report in the store.
        Returns True if a newer report is available or if the existing report needs a refresh. False otherwise

        It does not intentionally use the same mechanism as the legacy provider i.e. grype-db feed last_sync timestamp,
        as that's not an accurate measure. The last_sync timestamp reflects when a sync was performed,
        not if a new grype-db was synced. The more accurate approach is to compare the input with the report generation
        timestamp
        """
        # initialize store manager first
        store_manager = self.__store__(image)

        return store_manager.is_modified(session=db_session, since=since)

    def delete_image_vulnerabilities(self, image: Image, db_session):
        ImageVulnerabilitiesStore(image_object=image).delete_all(session=db_session)


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
        logger.warn(
            "No implementation found for configured provider %s. Falling back to default",
            provider_name,
        )
        provider_class = LegacyProvider

    PROVIDER = provider_class()
    logger.info("Initialized vulnerabilities provider: %s", PROVIDER.get_config_name())


def get_vulnerabilities_provider():
    if not PROVIDER:
        set_provider()

    return PROVIDER
