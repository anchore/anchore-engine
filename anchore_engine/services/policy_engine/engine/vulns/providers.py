import datetime
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
from anchore_engine.services.policy_engine.api.models import (
    Vulnerability as VulnerabilityModel,
    VulnerabilityMatch,
    Artifact,
    ImageVulnerabilitiesReport,
    VulnerabilitiesReportMetadata,
    CvssCombined,
    FixedArtifact,
    CvssScore,
    Match,
)
from anchore_engine import version

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
                    self._make_cvss_score(score)
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
                        self._make_cvss_score(score)
                        for score in vulnerability_cpe.parent.get_cvss_scores_nvd()
                    ]

                    vendor_scores = [
                        self._make_cvss_score(score)
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

        import uuid

        return ImageVulnerabilitiesReport(
            account_id=image.user_id,
            image_id=image_id,
            results=results,
            metadata=VulnerabilitiesReportMetadata(
                generated_at=datetime.datetime.utcnow(),
                uuid=str(uuid.uuid4()),
                generated_by=self._get_provider_metadata(),
            ),
            problems=[],
        )

    def _make_cvss_score(self, score):
        return CvssCombined(
            id=score.get("id"),
            cvss_v2=CvssScore.CvssScoreV1Schema().make(data=score.get("cvss_v2")),
            cvss_v3=CvssScore.CvssScoreV1Schema().make(data=score.get("cvss_v3")),
        )

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

    def _get_provider_metadata(self):
        return {
            "name": self.__class__.__name__,
            "version": version.version,
            "database_version": version.db_version,
        }


default_type = LegacyProvider


def get_vulnerabilities_provider():
    return default_type()
