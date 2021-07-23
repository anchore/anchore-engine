import datetime
import hashlib
import json
import re
import typing
import zlib
from collections import namedtuple
from typing import List

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    Sequence,
    String,
    Text,
    event,
    func,
    or_,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import joinedload, relationship, synonym

from anchore_engine.common.models.policy_engine import CVSS, NVDReference
from anchore_engine.db.entities.common import anchore_now_datetime
from anchore_engine.util.apk import compare_versions as apkg_compare_versions
from anchore_engine.util.deb import compare_versions as dpkg_compare_versions
from anchore_engine.util.langpack import compare_versions as langpack_compare_versions
from anchore_engine.util.rpm import compare_versions as rpm_compare_versions
from anchore_engine.utils import ensure_bytes, ensure_str

try:
    from anchore_engine.subsys import logger as log
except:
    import logging

    logger = logging.getLogger(__name__)
    log = logger

from .common import Base, StringJSON, UtilMixin, get_thread_scoped_session

DistroTuple = namedtuple("DistroTuple", ["distro", "version", "flavor"])

base_score_key = "base_score"
exploitability_score_key = "exploitability_score"
impact_score_key = "impact_score"
base_metrics_key = "base_metrics"
cvss_v3_key = "cvss_v3"
cvss_v2_key = "cvss_v2"


# Feeds
class FeedMetadata(Base, UtilMixin):
    __tablename__ = "feeds"

    name = Column(String, primary_key=True)
    description = Column(String)
    access_tier = Column(Integer)
    groups = relationship(
        "FeedGroupMetadata", back_populates="feed", cascade="all, delete-orphan"
    )
    last_full_sync = Column(DateTime)
    last_update = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    enabled = Column(Boolean, default=True)

    @classmethod
    def get_by_name(cls, session, name):
        return session.query(FeedMetadata).filter(FeedMetadata.name == name).scalar()

    def __repr__(self):
        return "<{}(name={}, access_tier={}, enabled={}, created_at={}>".format(
            self.__class__,
            self.name,
            self.access_tier,
            self.enabled,
            self.created_at.isoformat(),
        )

    def to_json(self, include_groups=True):
        j = super().to_json()

        if include_groups:
            j["groups"] = [g.to_json() for g in self.groups]
        else:
            j["groups"] = None

        return j


class FeedGroupMetadata(Base, UtilMixin):
    __tablename__ = "feed_groups"

    name = Column(String, primary_key=True)
    feed_name = Column(String, ForeignKey(FeedMetadata.name), primary_key=True)
    description = Column(String)
    access_tier = Column(Integer)
    last_sync = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_update = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    enabled = Column(Boolean, default=True)
    count = Column(
        BigInteger
    )  # To cache the row count of the group between feed syncs to avoid extra row count ops
    feed = relationship("FeedMetadata", back_populates="groups")

    def __repr__(self):
        return (
            "<{} name={}, feed={}, access_tier={}, enabled={}, created_at={}>".format(
                self.__class__,
                self.name,
                self.feed_name,
                self.access_tier,
                self.enabled,
                self.created_at,
            )
        )

    def to_json(self, include_feed=False):
        j = super().to_json()
        if include_feed:
            j["feed"] = self.feed.to_json(include_groups=False)  # Avoid the loop
        else:
            j["feed"] = None  # Ensure no non-serializable stuff

        return j


class GrypeDBFeedMetadata(Base):
    """
    A data model for persisting the current active grype db that the system should use across all policy-engine instances
    Each instance of policy engine witll use the active record in this table to determine the correct grype db
    Primary key is checksum, which refers to the checksum of the tar file
    The object url points to the location in object storage that the tar file is stored. This is used by processes that sync
    There should only ever be a single active record. More than one indicates an error in the system
    """

    __tablename__ = "grype_db_feed_metadata"

    archive_checksum = Column(String, primary_key=True)
    db_checksum = Column(String, nullable=True, index=True)
    schema_version = Column(String, nullable=False)
    object_url = Column(String, nullable=False)
    active = Column(Boolean, nullable=False)
    built_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=anchore_now_datetime, nullable=False)
    last_updated = Column(
        DateTime,
        default=anchore_now_datetime,
        onupdate=anchore_now_datetime,
        nullable=False,
    )
    synced_at = Column(DateTime, nullable=True)
    groups = Column(JSONB, default=[])


class GenericFeedDataRecord(Base):
    """
    A catch-all record for feed data without a specific schema mapping
    """

    __tablename__ = "feed_group_data"

    feed = Column(String, primary_key=True)
    group = Column(String, primary_key=True)
    id = Column(String, primary_key=True)
    created_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )
    data = Column(
        StringJSON, nullable=False
    )  # TODO: make this a JSON type for dbs that support it


class GemMetadata(Base):
    __tablename__ = "feed_data_gem_packages"

    name = Column(String, primary_key=True)
    id = Column(BigInteger)
    latest = Column(String)
    licenses_json = Column(StringJSON)
    authors_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def __repr__(self):
        return "<{} name={}, id={}, created_at={}>".format(
            self.__class__, self.name, self.id, self.created_at
        )

    def key_tuple(self):
        return self.name


class NpmMetadata(Base):
    __tablename__ = "feed_data_npm_packages"

    name = Column(String, primary_key=True)
    sourcepkg = Column(String)
    lics_json = Column(StringJSON)
    origins_json = Column(StringJSON)
    latest = Column(String)
    versions_json = Column(StringJSON)
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def __repr__(self):
        return "<{} name={}, sourcepkg={}, created_at={}>".format(
            self.__class__, self.name, self.sourcepkg, self.created_at
        )

    def key_tuple(self):
        return self.name


class Vulnerability(Base):
    """
    A vulnerability/CVE record. Can come from many sources. Includes some specific fields and also a general
    metadata field that is json encoded string
    """

    __tablename__ = "feed_data_vulnerabilities"

    id = Column(String, primary_key=True)  # CVE Id, RHSA id, etc
    namespace_name = Column(String, primary_key=True)  # e.g. centos, rhel, "debian"
    severity = Column(
        Enum(
            "Unknown",
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            name="vulnerability_severities",
        ),
        nullable=False,
    )
    description = Column(Text, nullable=True)
    link = Column(String, nullable=True)
    metadata_json = Column(StringJSON, nullable=True)
    cvss2_vectors = Column(String, nullable=True)
    cvss2_score = Column(Float, nullable=True)
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    vulnerable_in = relationship(
        "VulnerableArtifact", back_populates="parent", cascade="all, delete-orphan"
    )
    fixed_in = relationship(
        "FixedArtifact", back_populates="parent", cascade="all, delete-orphan"
    )

    @property
    def additional_metadata(self):
        if self.metadata_json:
            if isinstance(self.metadata_json, str):
                return json.loads(self.metadata_json)
            return self.metadata_json
        return None

    @additional_metadata.setter
    def additional_metadata(self, value):
        m = {}
        if value:
            if isinstance(value, str):
                m = json.loads(value)
            elif isinstance(value, dict):
                m.update(value)
            else:
                m = {"metadata": value}
        self.metadata_json = m
        # self.metadata_json = json.dumps(value)

    def __repr__(self):
        return "<{} id={}, namespace_name={}, severity={}, created_at={}>".format(
            self.__class__, self.id, self.namespace_name, self.severity, self.created_at
        )

    def current_package_vulnerabilities(self, db_session):
        """
        Return a list of all packages that are marked as vulnerable to this item
        :return: list of ImagePackageVulnerability objects
        """
        return (
            db_session.query(ImagePackageVulnerability)
            .filter(
                ImagePackageVulnerability.vulnerability_id == self.id,
                ImagePackageVulnerability.vulnerability_namespace_name
                == self.namespace_name,
            )
            .all()
        )

    def is_empty(self):
        """
        Can a package be vulnerable to this, or is it an empty definition.
        :return: boolean
        """
        # return not self.vulnerable_in and not self.fixed_in
        return not self.fixed_in

    def get_cvss_severity(self):
        sev = "Unknown"
        try:
            score = self.cvss2_score
            if score <= 3.9:
                sev = "Low"
            elif score <= 6.9:
                sev = "Medium"
            elif score <= 10.0:
                sev = "High"
            else:
                sev = "Unknown"
        except:
            sev = "Unknown"
        return sev

    def get_nvd_vulnerabilities(self, cvss_version=3, _nvd_cls=None, _cpe_cls=None):
        ret = []

        db = get_thread_scoped_session()
        if not _nvd_cls or not _cpe_cls:
            _nvd_cls, _cpe_cls = select_nvd_classes(db)

        try:
            cves = self.get_nvd_identifiers(_nvd_cls, _cpe_cls)
            nvd_records = db.query(_nvd_cls).filter(_nvd_cls.name.in_(cves)).all()
        except Exception as err:
            log.warn(
                "failed to gather NVD information for vulnerability due to exception: {}".format(
                    str(err)
                )
            )
            nvd_records = None

        if nvd_records:
            ret = nvd_records

        return ret

    def get_nvd_identifiers(self, _nvd_cls, _cpe_cls):
        cves = []
        try:
            if self.id.startswith("CVE-"):
                cves = [self.id]

            if self.metadata_json and self.metadata_json.get("CVE", []):
                for cve_el in self.metadata_json.get("CVE", []):
                    if type(cve_el) == dict:
                        # RHSA and ELSA internal elements are dicts
                        cve_id = cve_el.get("Name", None)
                    elif type(cve_el) == str:
                        # ALAS internal elements are just CVE ids
                        cve_id = cve_el
                    else:
                        cve_id = None

                    if cve_id and cve_id not in cves:
                        cves.append(cve_id)
        except Exception as err:
            log.warn(
                "failed to gather NVD information for vulnerability due to exception: {}".format(
                    str(err)
                )
            )

        return cves


class VulnerableArtifact(Base):
    """
    An entity affected by a vulnerability, typically an os or application package.
    Typically populated by CVEs with specific vulnerable packages enumerated.

    """

    __tablename__ = "feed_data_vulnerabilities_vulnerable_artifacts"

    vulnerability_id = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)
    name = Column(String, primary_key=True)
    version = Column(String, primary_key=True)
    version_format = Column(String)
    epochless_version = Column(String)
    include_previous_versions = Column(Boolean, default=True)
    parent = relationship("Vulnerability", back_populates="vulnerable_in")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (
        ForeignKeyConstraint(
            columns=(vulnerability_id, namespace_name),
            refcolumns=(Vulnerability.id, Vulnerability.namespace_name),
        ),
        {},
    )

    def __repr__(self):
        return "<{} name={}, version={}, vulnerability_id={}, namespace_name={}, created_at={}>".format(
            self.__class__,
            self.name,
            self.version,
            self.vulnerability_id,
            self.namespace_name,
            self.updated_at,
        )

    def match_and_vulnerable(self, package_obj):
        """
        Given a VulnerableArtifact record, is the given package object a match indicating that the package is vulnerable.

        :param vuln_obj:
        :param package_obj:
        :param has_fix: boolean indicating if there is a corresponding fix record
        :return:
        """
        vuln_obj = self
        if not isinstance(vuln_obj, VulnerableArtifact):
            raise TypeError(
                "Expected a VulnerableArtifact type, got: {}".format(type(vuln_obj))
            )

        dist = DistroNamespace.for_obj(package_obj)
        flavor = dist.flavor

        # Double-check names
        if (
            vuln_obj.name != package_obj.name
            and vuln_obj.name != package_obj.normalized_src_pkg
        ):
            log.warn(
                "Name mismatch in vulnerable check. This should not happen: Fix: {}, Package: {}, Package_Norm_Src: {}, Package_Src: {}".format(
                    vuln_obj.name,
                    package_obj.name,
                    package_obj.normalized_src_pkg,
                    package_obj.src_pkg,
                )
            )
            return False

        # Is it a catch-all record? Explicit 'None' or 'all' versions indicate all versions of the named package are vulnerable.
        # Or is it an exact version match?
        if vuln_obj.epochless_version in ["all", "None"] or (
            package_obj.fullversion == vuln_obj.epochless_version
            or package_obj.version == vuln_obj.epochless_version
        ):
            return True
        else:
            return False


class FixedArtifact(Base):
    """
    A record indicating an artifact version that marks a fix for a vulnerability
    """

    __tablename__ = "feed_data_vulnerabilities_fixed_artifacts"

    vulnerability_id = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)
    name = Column(String, primary_key=True)
    version = Column(String, primary_key=True)
    version_format = Column(String)
    epochless_version = Column(String)
    include_later_versions = Column(Boolean, default=True)
    parent = relationship("Vulnerability", back_populates="fixed_in")
    vendor_no_advisory = Column(Boolean, default=False)
    fix_metadata = Column(StringJSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    fix_observed_at = Column(DateTime)

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(vulnerability_id, namespace_name),
            refcolumns=(Vulnerability.id, Vulnerability.namespace_name),
        ),
        {},
    )

    @staticmethod
    def _fix_observed_at_update(mapper, connection, target):
        if not target.fix_observed_at and target.version and target.version != "None":
            target.fix_observed_at = datetime.datetime.utcnow()

    @classmethod
    def __declare_last__(cls):
        event.listen(cls, "before_update", cls._fix_observed_at_update)
        event.listen(cls, "before_insert", cls._fix_observed_at_update)

    def __repr__(self):
        return "<{} name={}, version={}, vulnerability_id={}, namespace_name={}, created_at={}>".format(
            self.__class__,
            self.name,
            self.version,
            self.vulnerability_id,
            self.namespace_name,
            self.created_at,
        )

    def match_but_not_fixed(self, package_obj):
        """
        Does the FixedArtifact match the package as a vulnerability such that the fix indicates the package is *not* fixed and is
        therefore vulnerable.

        :param fix_obj: as FixedArtifact record
        :param package_obj: an ImagePackage record
        :return: True if the names match and the fix record indicates the package is vulnerable and not fixed. False if no match or fix is applied and no vulnerability match
        """
        fix_obj = self
        if not isinstance(fix_obj, FixedArtifact):
            raise TypeError(
                "Expected a FixedArtifact type, got: {}".format(type(fix_obj))
            )

        dist = DistroNamespace.for_obj(package_obj)
        flavor = dist.flavor
        log.spew(
            "Package: {}, Fix: {}, Flavor: {}".format(
                package_obj.name, fix_obj.name, flavor
            )
        )

        # Double-check names
        if (
            fix_obj.name != package_obj.name
            and fix_obj.name != package_obj.normalized_src_pkg
        ):
            log.warn(
                "Name mismatch in fix check. This should not happen: Fix: {}, Package: {}, Package_Norm_Src: {}, Package_Src: {}".format(
                    fix_obj.name,
                    package_obj.name,
                    package_obj.normalized_src_pkg,
                    package_obj.src_pkg,
                )
            )
            return False

        # Handle the case where there is no version, indicating no fix available, all versions are vulnerable.
        # Is it a catch-all record? Explicit 'None' versions indicate all versions of the named package are vulnerable.
        if fix_obj.version == "None":
            return True

        # Is the package older than the fix?
        if (
            flavor == "RHEL"
        ):  # compare full package version with full fixed-in version, epoch handled in compare fn. fixes issue-265
            if rpm_compare_versions(package_obj.fullversion, fix_obj.version) < 0:
                log.spew(
                    "rpm Compared: {} < {}: True".format(
                        package_obj.fullversion, fix_obj.version
                    )
                )
                return True
        elif (
            flavor == "DEB"
        ):  # compare full package version with full fixed-in version, epoch handled in compare fn. fixes issue-265
            if dpkg_compare_versions(package_obj.fullversion, "lt", fix_obj.version):
                log.spew(
                    "dpkg Compared: {} < {}: True".format(
                        package_obj.fullversion, fix_obj.version
                    )
                )
                return True
        elif (
            flavor == "ALPINE"
        ):  # compare full package version with epochless fixed-in version
            if apkg_compare_versions(
                package_obj.fullversion, "lt", fix_obj.epochless_version
            ):
                log.spew(
                    "apkg Compared: {} < {}: True".format(
                        package_obj.fullversion, fix_obj.epochless_version
                    )
                )
                return True

        if package_obj.pkg_type in ["java", "maven", "npm", "gem", "python", "js"]:
            if package_obj.pkg_type in ["java", "maven"]:
                pomprops = package_obj.get_pom_properties()
                if pomprops:
                    pkgkey = "{}:{}".format(
                        pomprops.get("groupId"), pomprops.get("artifactId")
                    )
                    pkgversion = pomprops.get("version", None)
                else:
                    pkgversion = package_obj.version
            else:
                pkgversion = package_obj.fullversion

            if langpack_compare_versions(
                fix_obj.version, pkgversion, language=package_obj.pkg_type
            ):
                return True

        # Newer or the same
        return False


class NvdMetadata(Base):
    __tablename__ = "feed_data_nvd_vulnerabilities"

    name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)  # e.g. nvddb:2018"
    severity = Column(
        Enum(
            "Unknown",
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            name="vulnerability_severities",
        ),
        nullable=False,
        primary_key=True,
    )
    vulnerable_configuration = Column(StringJSON)
    vulnerable_software = Column(StringJSON)
    summary = Column(String)
    cvss = Column(StringJSON)
    cvssv3 = None
    cvssv2 = None
    vulnerable_cpes = relationship(
        "CpeVulnerability", back_populates="parent", cascade="all, delete-orphan"
    )
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def __repr__(self):
        return "<{} name={}, created_at={}>".format(
            self.__class__, self.name, self.created_at
        )

    @property
    def normalized_id(self):
        return self.name

    @property
    def description(self):
        return self.summary if self.summary else ""

    @property
    def references(self):
        return []

    def get_max_base_score_nvd(self, cvss_version=3):
        if cvss_version == 3:
            score = None
        elif cvss_version == 2:
            score = self.cvss.get(base_metrics_key, {}).get("score", None)
        else:
            log.warn(
                "invalid cvss version specified as input ({})".format(cvss_version)
            )
            score = None

        if score is None:
            ret = -1.0
        else:
            try:
                ret = float(score)
            except:
                ret = -1.0

        return ret

    def get_max_exploitability_score_nvd(self, cvss_version=3):
        return -1.0

    def get_max_impact_score_nvd(self, cvss_version=3):
        return -1.0

    def get_max_cvss_score_nvd(self, cvss_version=3):
        if cvss_version == 3:
            ret = {
                base_score_key: -1.0,
                exploitability_score_key: -1.0,
                impact_score_key: -1.0,
            }
        elif cvss_version == 2:
            ret = {
                base_score_key: self.get_max_base_score_nvd(cvss_version),
                exploitability_score_key: -1.0,
                impact_score_key: -1.0,
            }

        else:
            log.warn(
                "invalid cvss version specified as input ({})".format(cvss_version)
            )
            ret = {
                base_score_key: -1.0,
                exploitability_score_key: -1.0,
                impact_score_key: -1.0,
            }

        return ret

    def get_cvss_scores_nvd(self):
        ret = [
            {
                "id": self.name,
                cvss_v2_key: self.get_max_cvss_score_nvd(cvss_version=2),
                cvss_v3_key: self.get_max_cvss_score_nvd(cvss_version=3),
            }
        ]

        return ret

    def get_cvss_data_nvd(self):
        ret = [
            {
                "id": self.name,
                cvss_v2_key: self.cvssv2 if self.cvssv2 else None,
                cvss_v3_key: self.cvssv3 if self.cvssv3 else None,
            }
        ]

        return ret

    # vendor scores

    def get_max_base_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_exploitability_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_impact_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_cvss_score_vendor(self, cvss_version=3):
        ret = {
            base_score_key: -1.0,
            exploitability_score_key: -1.0,
            impact_score_key: -1.0,
        }
        return ret

    def get_cvss_scores_vendor(self):
        return []

    def get_cvss_data_vendor(self):
        return []

    @property
    def link(self):
        return "https://nvd.nist.gov/vuln/detail/{}".format(self.name)

    def key_tuple(self):
        return self.name

    def to_nvd_reference(self) -> NVDReference:
        """
        Returns an NVDReference object from this nvd vulnerability. Function to be used by non-nvd vulnerabilities for
        populating an nvd reference
        """

        return NVDReference(
            vulnerability_id=self.name,
            severity=self.severity,
            link=self.link,
            cvss=self.get_all_cvss(),
        )

    def get_all_cvss(self) -> List[CVSS]:
        """
        Returns a list of CVSS objects for this vulnerability
        """
        return [
            CVSS(
                version="2.0",
                base_score=self.get_max_base_score_nvd(2),
                exploitability_score=-1.0,
                impact_score=-1.0,
            )
        ]

    def get_all_nvd_references(self):
        """
        Compatibility method. Returns empty list since an nvd vuln doesn't have any nvd refrences
        """
        return []


class NvdV2Metadata(Base):
    __tablename__ = "feed_data_nvdv2_vulnerabilities"

    name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)  # e.g. nvddb:2018"
    severity = Column(
        Enum(
            "Unknown",
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            name="vulnerability_severities",
        ),
        nullable=False,
        index=True,
    )
    description = Column(String, nullable=True)
    cvss_v2 = Column(JSON, nullable=True)
    cvss_v3 = Column(JSON, nullable=True)
    link = Column(String, nullable=True)
    references = Column(JSON, nullable=True)
    vulnerable_cpes = relationship(
        "CpeV2Vulnerability", back_populates="parent", cascade="all, delete-orphan"
    )
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def __repr__(self):
        return "<{} name={}, created_at={}>".format(
            self.__class__, self.name, self.created_at
        )

    @property
    def normalized_id(self):
        return self.name

    def _get_score(self, metric, score_key):
        if metric:
            score = metric.get(base_metrics_key).get(score_key, -1.0)
            try:
                score = float(score)
            except:
                score = -1.0
        else:
            score = -1.0

        return score

    def _get_metric(self, cvss_version=3):
        metric = None
        if cvss_version == 3:
            metric = self.cvss_v3
        elif cvss_version == 2:
            metric = self.cvss_v2
        else:
            log.warn(
                "invalid cvss version specified as input ({})".format(cvss_version)
            )

        return metric

    def get_max_base_score_nvd(self, cvss_version=3):
        metric = self._get_metric(cvss_version)
        return self._get_score(metric, base_score_key)

    def get_max_exploitability_score_nvd(self, cvss_version=3):
        metric = self._get_metric(cvss_version)
        return self._get_score(metric, exploitability_score_key)

    def get_max_impact_score_nvd(self, cvss_version=3):
        metric = self._get_metric(cvss_version)
        return self._get_score(metric, impact_score_key)

    def get_max_cvss_score_nvd(self, cvss_version=3):
        metric = self._get_metric(cvss_version)
        ret = {
            base_score_key: self._get_score(metric, base_score_key),
            exploitability_score_key: self._get_score(metric, exploitability_score_key),
            impact_score_key: self._get_score(metric, impact_score_key),
        }

        return ret

    def get_cvss_scores_nvd(self):
        ret = [
            {
                "id": self.name,
                cvss_v2_key: self.get_max_cvss_score_nvd(cvss_version=2),
                cvss_v3_key: self.get_max_cvss_score_nvd(cvss_version=3),
            }
        ]

        return ret

    def get_cvss_data_nvd(self):
        ret = [
            {
                "id": self.name,
                cvss_v2_key: self._get_metric(cvss_version=2),
                cvss_v3_key: self._get_metric(cvss_version=3),
            }
        ]

        return ret

    # vendor scores

    def get_max_base_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_exploitability_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_impact_score_vendor(self, cvss_version=3):
        return -1.0

    def get_max_cvss_score_vendor(self, cvss_version=3):
        ret = {
            base_score_key: -1.0,
            exploitability_score_key: -1.0,
            impact_score_key: -1.0,
        }
        return ret

    def get_cvss_scores_vendor(self):
        return []

    def get_cvss_data_vendor(self):
        return []

    def key_tuple(self):
        return self.name

    def to_nvd_reference(self) -> NVDReference:
        """
        Returns an NVDReference object from this nvd vulnerability. Function to be used by non-nvd vulnerabilities for
        populating an nvd reference

        cvss_v3 column format
        {
          "base_metrics": {
            "attack_complexity": "LOW",
            "attack_vector": "LOCAL",
            "availability_impact": "HIGH",
            "base_score": 7.8,
            "base_severity": "High",
            "confidentiality_impact": "HIGH",
            "exploitability_score": 1.8,
            "impact_score": 5.9,
            "integrity_impact": "HIGH",
            "privileges_required": "LOW",
            "scope": "UNCHANGED",
            "user_interaction": "NONE"
          },
          "vector_string": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
          "version": "3.1"
        }

        cvss_v2 column format
        {
          "additional_information": {
            "ac_insuf_info": false,
            "obtain_all_privilege": false,
            "obtain_other_privilege": false,
            "obtain_user_privilege": false,
            "user_interaction_required": false
          },
          "base_metrics": {
            "access_complexity": "LOW",
            "access_vector": "LOCAL",
            "authentication": "NONE",
            "availability_impact": "COMPLETE",
            "base_score": 7.2,
            "confidentiality_impact": "COMPLETE",
            "exploitability_score": 3.9,
            "impact_score": 10,
            "integrity_impact": "COMPLETE"
          },
          "severity": "High",
          "vector_string": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
          "version": "2.0"
        }
        """
        nvd_ref = NVDReference(
            vulnerability_id=self.name,
            severity=self.severity,
            link=self.link,
            cvss=self.get_all_cvss(),
        )

        return nvd_ref

    def get_all_cvss(self) -> List[CVSS]:
        """
        Returns a list of CVSS objects for this vulnerability
        """
        results = []
        v2_metric = self._get_metric(cvss_version=2)
        if v2_metric:
            results.append(
                CVSS(
                    version=v2_metric.get("version", "2.0"),
                    vector=v2_metric.get("vector_string"),
                    base_score=self._get_score(v2_metric, base_score_key),
                    exploitability_score=self._get_score(
                        v2_metric, exploitability_score_key
                    ),
                    impact_score=self._get_score(v2_metric, impact_score_key),
                )
            )

        v3_metric = self._get_metric(cvss_version=3)
        if v3_metric:
            results.append(
                CVSS(
                    version=v3_metric.get("version", "3.0"),
                    vector=v3_metric.get("vector_string"),
                    base_score=self._get_score(v3_metric, base_score_key),
                    exploitability_score=self._get_score(
                        v3_metric, exploitability_score_key
                    ),
                    impact_score=self._get_score(v3_metric, impact_score_key),
                )
            )

        return results

    def get_all_nvd_references(self):
        """
        Compatibility method. Returns empty list since an nvd vuln doesn't have any nvd refrences
        """
        return []


class VulnDBMetadata(Base):
    __tablename__ = "feed_data_vulndb_vulnerabilities"

    name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)  # e.g. vulndb:vulnerabilities
    severity = Column(
        Enum(
            "Unknown",
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            name="vulnerability_severities",
        ),
        nullable=False,
        index=True,
    )
    title = Column(String, nullable=True)
    description = Column(String, nullable=True)
    solution = Column(String, nullable=True)
    vendor_product_info = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    vulnerable_packages = Column(JSON, nullable=True)
    vulnerable_libraries = Column(JSON, nullable=True)
    vendor_cvss_v2 = Column(JSON, nullable=True)
    vendor_cvss_v3 = Column(JSON, nullable=True)
    nvd = Column(JSON, nullable=True)
    vuln_metadata = Column(JSON, nullable=True)
    cpes = relationship(
        "VulnDBCpe", back_populates="parent", cascade="all, delete-orphan"
    )
    # unaffected_cpes = relationship('VulnDBUnaffectedCpe', back_populates='parent', cascade='all, delete-orphan')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    def __repr__(self):
        return "<{} name={}, created_at={}>".format(
            self.__class__, self.name, self.created_at
        )

    @property
    def normalized_id(self):
        """normalized_id will inspect the in coming external
        references and return a cve id in the case of a single
        match against vulndb information.
        """
        res = _get_one_or_none("source", "CVE ID", self.references)
        if res and res.get("url"):
            # findall should return a single id list ['2020-11989']
            cve_id_col = re.findall(r"\=(\d+\-\d+)", res.get("url"))
            if cve_id_col:
                return "CVE-" + cve_id_col[0]

        return self.name

    @property
    def referenced_cves(self) -> typing.List[str]:
        """
        Returns all referenced CVE IDs from the record, may be zero, one, or many.

        :return: List[Str]
        """
        ids = set()

        # References is a list of objects each with a potential "source" key
        for reference in [
            ref for ref in self.references if ref.get("source") == "CVE ID"
        ]:
            url = reference.get("url")
            if url:
                # findall should return a single id list ['2020-11989']
                cve_id_col = re.findall(r"\=(\d+\-\d+)", url)
                if cve_id_col:
                    ids.add("CVE-" + cve_id_col[0])

        return list(ids)

    def _get_max_cvss_v3_metric_nvd(self):
        cvss_v3 = None
        if self.nvd:
            if len(self.nvd) == 1:
                cvss_v3 = self.nvd[0].get(cvss_v3_key, None)
            else:
                max_score = None
                for nvd_item in self.nvd:
                    if nvd_item.get(cvss_v3_key, None):
                        if (
                            not max_score
                            or nvd_item.get(cvss_v3_key)
                            .get(base_metrics_key)
                            .get(base_score_key)
                            > max_score
                        ):
                            max_score = (
                                nvd_item.get(cvss_v3_key)
                                .get(base_metrics_key)
                                .get(base_score_key)
                            )
                            cvss_v3 = nvd_item.get(cvss_v3_key)
                        else:
                            continue
        return cvss_v3

    def _get_max_cvss_v2_metric_nvd(self):
        cvss_v2 = None
        if self.nvd:
            if len(self.nvd) == 1:
                cvss_v2 = self.nvd[0].get(cvss_v2_key, None)
            else:
                max_score = None
                for nvd_item in self.nvd:
                    if nvd_item.get(cvss_v2_key, None):
                        if (
                            not max_score
                            or nvd_item.get(cvss_v2_key)
                            .get(base_metrics_key)
                            .get(base_score_key)
                            > max_score
                        ):
                            max_score = (
                                nvd_item.get(cvss_v2_key)
                                .get(base_metrics_key)
                                .get(base_score_key)
                            )
                            cvss_v2 = nvd_item.get(cvss_v2_key)
                        else:
                            continue
        return cvss_v2

    def _get_max_cvss_metric_nvd(self, cvss_version):
        """
          [
            {
              "id": "CVE-2019-5440",
              "cvss_v2": {
                "version": "2.0",
                "vector_string": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "base_metrics": {
                  "base_score": 6.8,
                  "exploitability_score": 8.6,
                  "impact_score": 6.4,
                  "severity": "Medium"
                  ...
                }
              },
              "cvss_v3": {
                "version": "3.0",
                "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_metrics": {
                  "base_score": 8.1,
                  "exploitability_score": 2.2,
                  "impact_score": 6.0,
                  "severity": "High"
                  ...
                }
              }
            },
            {
              "id": "CVE-2019-5441",
              "cvss_v2": {
                "version": "2.0",
                "vector_string": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "base_metrics": {
                  "base_score": 6.8,
                  "exploitability_score": 8.6,
                  "impact_score": 6.4,
                  "severity": "Medium"
                  ...
                }
              },
              "cvss_v3": {
                "version": "3.0",
                "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_metrics": {
                  "base_score": 8.1,
                  "exploitability_score": 2.2,
                  "impact_score": 6.0,
                  "severity": "High"
                  ...
                }
              }
            },
          ]

        :param cvss_version:
        :return:
        """

        metric = None
        if cvss_version == 3:
            metric = self._get_max_cvss_v3_metric_nvd()
        elif cvss_version == 2:
            metric = self._get_max_cvss_v2_metric_nvd()
        else:
            log.warning(
                "invalid cvss version specified as input ({})".format(cvss_version)
            )

        return metric

    def _get_max_cvss_v3_metric_rbs(self):
        cvss_v3 = None
        if self.vendor_cvss_v3:
            if len(self.vendor_cvss_v3) == 1:
                cvss_v3 = self.vendor_cvss_v3[0]
            else:
                max_score = None
                for cvss_item in self.vendor_cvss_v3:
                    if (
                        not max_score
                        or cvss_item.get(base_metrics_key).get(base_score_key)
                        > max_score
                    ):
                        max_score = cvss_item.get(base_metrics_key).get(base_score_key)
                        cvss_v3 = cvss_item
                    else:
                        continue
        return cvss_v3

    def _get_highest_cvss_v2_rbs(self):
        cvss_v2 = None
        if self.vendor_cvss_v2:
            if len(self.vendor_cvss_v2) == 1:
                cvss_v2 = self.vendor_cvss_v2[0]
            else:
                max_score = None
                for cvss_item in self.vendor_cvss_v2:
                    if (
                        not max_score
                        or cvss_item.get(base_metrics_key).get(base_score_key)
                        > max_score
                    ):
                        max_score = cvss_item.get(base_metrics_key).get(base_score_key)
                        cvss_v2 = cvss_item
                    else:
                        continue
        return cvss_v2

    def _get_max_cvss_metric_rbs(self, cvss_version):
        """
          cvss_version is a list in format
          [
            {
              "version": "3.0",
              "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "base_metrics": {
                "base_score": 8.1,
                "exploitability_score": 2.2,
                "impact_score": 6.0,
                "severity": "High"
                ...
              }
            },
            {
              "version": "3.0",
              "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "base_metrics": {
                "base_score": 8.1,
                "exploitability_score": 2.2,
                "impact_score": 6.0,
                "severity": "High"
                ...
              }
            }
          ]
        :param cvss_version:
        :return:
        """

        metric = None
        if cvss_version == 3:
            metric = self._get_max_cvss_v3_metric_rbs()
        elif cvss_version == 2:
            metric = self._get_highest_cvss_v2_rbs()
        else:
            log.warning(
                "invalid cvss version specified as input ({})".format(cvss_version)
            )

        return metric

    def _get_score(self, metric, score_key):
        if metric:
            score = metric.get(base_metrics_key).get(score_key, -1.0)
            try:
                score = float(score)
            except:
                score = -1.0
        else:
            score = -1.0

        return score

    # nvd scores

    def get_max_base_score_nvd(self, cvss_version=3):
        metric = self._get_max_cvss_metric_nvd(cvss_version)
        return self._get_score(metric, base_score_key)

    def get_max_exploitability_score_nvd(self, cvss_version=3):
        metric = self._get_max_cvss_metric_nvd(cvss_version)
        return self._get_score(metric, exploitability_score_key)

    def get_max_impact_score_nvd(self, cvss_version=3):
        metric = self._get_max_cvss_metric_nvd(cvss_version)
        return self._get_score(metric, impact_score_key)

    def get_max_cvss_score_nvd(self, cvss_version=3):
        metric = self._get_max_cvss_metric_nvd(cvss_version)
        ret = {
            base_score_key: self._get_score(metric, base_score_key),
            exploitability_score_key: self._get_score(metric, exploitability_score_key),
            impact_score_key: self._get_score(metric, impact_score_key),
        }

        return ret

    def get_cvss_scores_nvd(self):
        result = []
        for nvd_cvss_item in self.get_cvss_data_nvd():
            """
            nvd_cvss_item is in the format
            {
              "id": "CVE-2019-5441",
              "cvss_v2": {
                "version": "2.0",
                "vector_string": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "base_metrics": {
                  "base_score": 6.8,
                  "exploitability_score": 8.6,
                  "impact_score": 6.4,
                  "severity": "Medium"
                  ...
                }
              },
              "cvss_v3": {
                "version": "3.0",
                "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_metrics": {
                  "base_score": 8.1,
                  "exploitability_score": 2.2,
                  "impact_score": 6.0,
                  "severity": "High"
                  ...
                }
              }
            }
            """
            cvss_v2_metric = nvd_cvss_item.get(cvss_v2_key, None)
            cvss_v3_metric = nvd_cvss_item.get(cvss_v3_key, None)
            score_item = {
                "id": nvd_cvss_item.get("id"),
                cvss_v2_key: {
                    base_score_key: self._get_score(cvss_v2_metric, base_score_key),
                    exploitability_score_key: self._get_score(
                        cvss_v2_metric, exploitability_score_key
                    ),
                    impact_score_key: self._get_score(cvss_v2_metric, impact_score_key),
                },
                cvss_v3_key: {
                    base_score_key: self._get_score(cvss_v3_metric, base_score_key),
                    exploitability_score_key: self._get_score(
                        cvss_v3_metric, exploitability_score_key
                    ),
                    impact_score_key: self._get_score(cvss_v3_metric, impact_score_key),
                },
            }
            result.append(score_item)

        return result

    def get_cvss_data_nvd(self):
        return self.nvd if self.nvd else []

    # vendor scores

    def get_max_base_score_vendor(self, cvss_version=3):
        metric = self._get_max_cvss_metric_rbs(cvss_version)
        return self._get_score(metric, base_score_key)

    def get_max_exploitability_score_vendor(self, cvss_version=3):
        metric = self._get_max_cvss_metric_rbs(cvss_version)
        return self._get_score(metric, exploitability_score_key)

    def get_max_impact_score_vendor(self, cvss_version=3):
        metric = self._get_max_cvss_metric_rbs(cvss_version)
        return self._get_score(metric, impact_score_key)

    def get_max_cvss_score_vendor(self, cvss_version=3):
        metric = self._get_max_cvss_metric_rbs(cvss_version)
        ret = {
            base_score_key: self._get_score(metric, base_score_key),
            exploitability_score_key: self._get_score(metric, exploitability_score_key),
            impact_score_key: self._get_score(metric, impact_score_key),
        }

        return ret

    def get_cvss_scores_vendor(self):
        results = []

        if self.vendor_cvss_v2:
            for cvss_v2_item in self.vendor_cvss_v2:
                # create a new record for every single score as there could be a different number of v2 and v3 scores and its not clear which belong as a pair
                results.append(
                    {
                        "id": self.name,
                        cvss_v2_key: {
                            base_score_key: self._get_score(
                                cvss_v2_item, base_score_key
                            ),
                            exploitability_score_key: self._get_score(
                                cvss_v2_item, exploitability_score_key
                            ),
                            impact_score_key: self._get_score(
                                cvss_v2_item, impact_score_key
                            ),
                        },
                        cvss_v3_key: {
                            base_score_key: -1.0,
                            exploitability_score_key: -1.0,
                            impact_score_key: -1.0,
                        },
                    }
                )

        if self.vendor_cvss_v3:
            for cvss_v3_item in self.vendor_cvss_v3:
                # create a new record for every single score as there could be a different number of v2 and v3 scores and its not clear which belong as a pair
                results.append(
                    {
                        "id": self.name,
                        cvss_v2_key: {
                            base_score_key: -1.0,
                            exploitability_score_key: -1.0,
                            impact_score_key: -1.0,
                        },
                        cvss_v3_key: {
                            base_score_key: self._get_score(
                                cvss_v3_item, base_score_key
                            ),
                            exploitability_score_key: self._get_score(
                                cvss_v3_item, exploitability_score_key
                            ),
                            impact_score_key: self._get_score(
                                cvss_v3_item, impact_score_key
                            ),
                        },
                    }
                )

        return results

    def get_cvss_data_vendor(self):
        results = []

        if self.vendor_cvss_v2:
            for cvss_v2_item in self.vendor_cvss_v2:
                results.append(
                    {"id": self.name, cvss_v2_key: cvss_v2_item, cvss_v3_key: None}
                )

        if self.vendor_cvss_v3:
            for cvss_v3_item in self.vendor_cvss_v3:
                results.append(
                    {"id": self.name, cvss_v2_key: None, cvss_v3_key: cvss_v3_item}
                )

        return results

    @property
    def link(self):
        return None

    @property
    def vulnerable_cpes(self):
        return [cpe for cpe in self.cpes if cpe.is_affected]

    def key_tuple(self):
        return self.name

    def to_nvd_reference(self):
        """
        Compatibility method. Returns None since a VulnDB vulnerability cannot be coerced into NVDReference
        """
        return None

    def get_all_cvss(self) -> List[CVSS]:
        """
        Returns a list of CVSS objects from vendor_cvss_v2 and vendor_cvss_v3 columns of this vulnerability

        vendor_cvss_v3 column is in format
          [
            {
              "version": "3.0",
              "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "base_metrics": {
                "base_score": 8.1,
                "exploitability_score": 2.2,
                "impact_score": 6.0,
                "severity": "High"
                ...
              }
            }
          ]
        """
        results = []

        for v2_metric in self.vendor_cvss_v2:
            results.append(
                CVSS(
                    version=v2_metric.get("version", "2.0"),
                    vector=v2_metric.get("vector_string"),
                    base_score=self._get_score(v2_metric, base_score_key),
                    exploitability_score=self._get_score(
                        v2_metric, exploitability_score_key
                    ),
                    impact_score=self._get_score(v2_metric, impact_score_key),
                )
            )

        for v3_metric in self.vendor_cvss_v3:
            results.append(
                CVSS(
                    version=v3_metric.get("version", "3.0"),
                    vector=v3_metric.get("vector_string"),
                    base_score=self._get_score(v3_metric, base_score_key),
                    exploitability_score=self._get_score(
                        v3_metric, exploitability_score_key
                    ),
                    impact_score=self._get_score(v3_metric, impact_score_key),
                )
            )

        return results

    def get_all_nvd_references(self) -> List[NVDReference]:
        """
        Returns all NVDReferences object from this VulnDB vulnerability. Function to be used for populating the nvd references
        for VulnDB vulnerabilities only

        nvd column is in the format
          [
            {
              "id": "CVE-2019-5441",
              "cvss_v2": {
                "version": "2.0",
                "vector_string": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "base_metrics": {
                  "base_score": 6.8,
                  "exploitability_score": 8.6,
                  "impact_score": 6.4,
                  "severity": "Medium"
                  ...
                }
              },
              "cvss_v3": {
                "version": "3.0",
                "vector_string": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_metrics": {
                  "base_score": 8.1,
                  "exploitability_score": 2.2,
                  "impact_score": 6.0,
                  "severity": "High"
                  ...
                }
              }
            }
          ]
        """
        results = []
        for nvd_cvss_item in self.get_cvss_data_nvd():
            nvd_ref = NVDReference(vulnerability_id=nvd_cvss_item.get("id"), cvss=[])
            v2_metric = nvd_cvss_item.get(cvss_v2_key, None)
            if v2_metric:
                nvd_ref.cvss.append(
                    CVSS(
                        version=v2_metric.get("version", "2.0"),
                        vector=v2_metric.get("vector_string"),
                        base_score=self._get_score(v2_metric, base_score_key),
                        exploitability_score=self._get_score(
                            v2_metric, exploitability_score_key
                        ),
                        impact_score=self._get_score(v2_metric, impact_score_key),
                    )
                )

            v3_metric = nvd_cvss_item.get(cvss_v3_key, None)
            if v3_metric:
                nvd_ref.cvss.append(
                    CVSS(
                        version=v3_metric.get("version", "3.0"),
                        vector=v3_metric.get("vector_string"),
                        base_score=self._get_score(v3_metric, base_score_key),
                        exploitability_score=self._get_score(
                            v3_metric, exploitability_score_key
                        ),
                        impact_score=self._get_score(v3_metric, impact_score_key),
                    )
                )

            results.append(nvd_ref)

        return results


class CpeVulnerability(Base):
    __tablename__ = "feed_data_cpe_vulnerabilities"

    feed_name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)
    vulnerability_id = Column(String, primary_key=True)
    severity = Column(
        Enum(
            "Unknown",
            "Negligible",
            "Low",
            "Medium",
            "High",
            "Critical",
            name="vulnerability_severities",
        ),
        nullable=False,
        primary_key=True,
    )
    cpetype = Column(String, primary_key=True)
    vendor = Column(String, primary_key=True)
    name = Column(String, primary_key=True)
    version = Column(String, primary_key=True)
    update = Column(String, primary_key=True)
    meta = Column(String, primary_key=True)
    link = Column(String, nullable=True)
    parent = relationship("NvdMetadata", back_populates="vulnerable_cpes")
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (
        ForeignKeyConstraint(
            columns=(vulnerability_id, namespace_name, severity),
            refcolumns=(
                NvdMetadata.name,
                NvdMetadata.namespace_name,
                NvdMetadata.severity,
            ),
        ),
        Index("ix_feed_data_cpe_vulnerabilities_name_version", name, version),
        Index(
            "ix_feed_data_cpe_vulnerabilities_fk",
            vulnerability_id,
            namespace_name,
            severity,
        ),
        {},
    )

    def __repr__(self):
        return "<{} feed_name={}, vulnerability_id={}, name={}, version={}, created_at={}>".format(
            self.__class__,
            self.feed_name,
            self.vulnerability_id,
            self.name,
            self.version,
            self.created_at.isoformat(),
        )

    def get_cpestring(self):
        ret = None
        try:
            final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
            final_cpe[1] = self.cpetype
            final_cpe[2] = self.vendor
            final_cpe[3] = self.name
            final_cpe[4] = self.version
            final_cpe[5] = self.update
            final_cpe[6] = self.meta
            ret = ":".join(final_cpe)
        except:
            ret = None

        return ret

    def get_fixed_in(self):
        return []


class CpeV2Vulnerability(Base):
    __tablename__ = "feed_data_cpev2_vulnerabilities"

    feed_name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)
    vulnerability_id = Column(String, primary_key=True)
    part = Column(String, primary_key=True)
    vendor = Column(String, primary_key=True)
    product = Column(String, primary_key=True)
    name = synonym("product")
    version = Column(String, primary_key=True)
    update = Column(String, primary_key=True)
    edition = Column(String, primary_key=True)
    language = Column(String, primary_key=True)
    sw_edition = Column(String, primary_key=True)
    target_sw = Column(String, primary_key=True)
    target_hw = Column(String, primary_key=True)
    other = Column(String, primary_key=True)
    parent = relationship("NvdV2Metadata", back_populates="vulnerable_cpes")
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (
        ForeignKeyConstraint(
            columns=(vulnerability_id, namespace_name),
            refcolumns=(NvdV2Metadata.name, NvdV2Metadata.namespace_name),
        ),
        Index("ix_feed_data_cpev2_vulnerabilities_name_version", product, version),
        Index(
            "ix_feed_data_cpev2_vulnerabilities_fk", vulnerability_id, namespace_name
        ),
        {},
    )

    def __repr__(self):
        return "<{} feed_name={}, vulnerability_id={}, product={}, version={}, created_at={}>".format(
            self.__class__,
            self.feed_name,
            self.vulnerability_id,
            self.product,
            self.version,
            self.created_at.isoformat(),
        )

    def get_cpestring(self):
        ret = None
        try:
            final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
            final_cpe[1] = "/" + self.part
            final_cpe[2] = self.vendor
            final_cpe[3] = self.product
            final_cpe[4] = self.version
            final_cpe[5] = self.update
            final_cpe[6] = self.other
            ret = ":".join(final_cpe)
        except:
            ret = None

        return ret

    def get_cpe23string(self):
        ret = None
        try:
            final_cpe = [
                "cpe",
                "2.3",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
            ]
            final_cpe[2] = self.part
            final_cpe[3] = self.vendor
            final_cpe[4] = self.product
            final_cpe[5] = self.version
            final_cpe[6] = self.update
            final_cpe[7] = self.edition
            final_cpe[8] = self.language
            final_cpe[9] = self.sw_edition
            final_cpe[10] = self.target_sw
            final_cpe[11] = self.target_hw
            final_cpe[12] = self.other
            ret = ":".join(final_cpe)
        except:
            ret = None

        return ret

    def get_fixed_in(self):
        return []


class VulnDBCpe(Base):
    __tablename__ = "feed_data_vulndb_cpes"

    feed_name = Column(String, primary_key=True)
    namespace_name = Column(String, primary_key=True)
    vulnerability_id = Column(String, primary_key=True)
    part = Column(String, primary_key=True)
    vendor = Column(String, primary_key=True)
    product = Column(String, primary_key=True)
    name = synonym("product")
    version = Column(String, primary_key=True)
    update = Column(String, primary_key=True)
    edition = Column(String, primary_key=True)
    language = Column(String, primary_key=True)
    sw_edition = Column(String, primary_key=True)
    target_sw = Column(String, primary_key=True)
    target_hw = Column(String, primary_key=True)
    other = Column(String, primary_key=True)
    is_affected = Column(Boolean, primary_key=True)
    parent = relationship("VulnDBMetadata", back_populates="cpes")
    created_at = Column(
        DateTime, default=datetime.datetime.utcnow
    )  # TODO: make these server-side
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (
        ForeignKeyConstraint(
            columns=(vulnerability_id, namespace_name),
            refcolumns=(VulnDBMetadata.name, VulnDBMetadata.namespace_name),
        ),
        Index("ix_feed_data_vulndb_affected_cpes_product_version", product, version),
        Index("ix_feed_data_vulndb_affected_cpes_fk", vulnerability_id, namespace_name),
        {},
    )

    def __repr__(self):
        return "<{} feed_name={}, vulnerability_id={}, product={}, version={}, created_at={}>".format(
            self.__class__,
            self.feed_name,
            self.vulnerability_id,
            self.product,
            self.version,
            self.created_at.isoformat(),
        )

    def get_cpestring(self):
        ret = None
        try:
            if self.sw_edition or self.target_sw or self.target_hw or self.other:
                edition = "~{}~{}~{}~{}~{}".format(
                    self.edition,
                    self.sw_edition,
                    self.target_sw,
                    self.target_hw,
                    self.other,
                )
            else:
                edition = self.edition

            uri_parts = [
                "cpe",
                "/" + self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                edition,
                self.language,
            ]

            uri = ":".join(uri_parts)
            ret = uri.strip(":")  # remove any trailing :
        except:
            ret = None

        return ret

    def get_cpe23string(self):
        ret = None
        try:
            final_cpe = [
                "cpe",
                "2.3",
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                self.edition,
                self.language,
                self.sw_edition,
                self.target_sw,
                self.target_hw,
                self.other,
            ]

            ret = ":".join(final_cpe)
        except:
            ret = None

        return ret

    def get_fixed_in(self):
        return [
            cpe.version
            for cpe in self.parent.cpes
            if not cpe.is_affected
            and cpe.product == self.product
            and cpe.vendor == self.vendor
            and cpe.part == self.part
        ]


# Analysis Data for Images


class ImagePackage(Base):
    """
    A package detected in an image by analysis
    """

    __tablename__ = "image_packages"

    image_id = Column(String, primary_key=True)
    image_user_id = Column(String, primary_key=True)

    name = Column(String, primary_key=True)
    version = Column(String, primary_key=True)
    pkg_type = Column(String, primary_key=True)  # RHEL, DEB, APK, etc.
    arch = Column(String, default="N/A", primary_key=True)
    pkg_path = Column(String, default="pkgdb", primary_key=True)

    pkg_path_hash = Column(String)  # The sha256 hash of the path in hex

    # Could pkg namespace be diff than os? e.g. rpms in Deb?
    distro_name = Column(String)
    distro_version = Column(String)
    like_distro = Column(String)

    fullversion = Column(String)
    release = Column(String, default="")
    origin = Column(String, default="N/A")
    src_pkg = Column(String, default="N/A")
    normalized_src_pkg = Column(String, default="N/A")

    metadata_json = Column(StringJSON)

    license = Column(String, default="N/A")
    size = Column(BigInteger, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    vulnerabilities = relationship(
        "ImagePackageVulnerability",
        back_populates="package",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )
    image = relationship("Image", back_populates="packages")
    pkg_db_entries = relationship(
        "ImagePackageManifestEntry",
        backref="package",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        Index(
            "ix_image_package_distronamespace",
            name,
            version,
            distro_name,
            distro_version,
            normalized_src_pkg,
        ),
        # TODO: add this index for feed sync performance, needs to be re-tested with new package usage
        #  Index('ix_image_package_distro_pkgs', distro_name, distro_version, name, normalized_src_pkg, version),
        {},
    )

    _distro_namespace = None

    @property
    def distro_namespace_meta(self):
        if not self._distro_namespace:
            self._distro_namespace = DistroNamespace.for_obj(self)
        return self._distro_namespace

    @property
    def distro_namespace(self):
        if self.distro_name and self.distro_version:
            return self.distro_name + ":" + self.distro_version
        else:
            return None

    def get_pom_properties(self):
        if not self.metadata_json:
            return None

        filebuf = self.metadata_json.get("pom.properties", "")
        props = {}
        for line in filebuf.splitlines():
            # line = anchore_engine.utils.ensure_str(line)
            if not re.match(r"\s*(#.*)?$", line):
                kv = line.split("=")
                key = kv[0].strip()
                value = "=".join(kv[1:]).strip()
                props[key] = value
        return props

    def find_vulnerabilities(self):
        """
        Given an ImagePackage object, return the vulnerabilities that it matches.

        :param package_obj:
        :return: list of Vulnerability objects
        """
        # ts = time.time()

        # package_obj = self
        log.debug(
            "Finding vulnerabilities for package: {} - {}".format(
                self.name, self.version
            )
        )

        matches = []
        db = get_thread_scoped_session()

        # decide what type of scan(s) to perform
        do_langscan = do_osscan = False

        pkgkey = pkgversion = None
        likematch = None
        if self.pkg_type in ["java", "maven"]:
            # search for maven hits
            if self.metadata_json:
                pombuf = self.metadata_json.get("pom.properties", "")
                if pombuf:
                    pomprops = self.get_pom_properties()
                    pkgkey = "{}:{}".format(
                        pomprops.get("groupId"), pomprops.get("artifactId")
                    )
                    pkgversion = pomprops.get("version", None)
                    likematch = "%java%"
                    do_langscan = True

        elif self.pkg_type in [
            "ruby",
            "gem",
            "npm",
            "js",
            "python",
            "nuget",
            "dotnet",
            "binary",
            "go",
        ]:
            pkgkey = self.name
            pkgversion = self.version
            if self.pkg_type in ["ruby", "gem"]:
                likematch = "%gem%"
                do_langscan = True
            elif self.pkg_type in ["npm", "js"]:
                likematch = "%npm%"
                do_langscan = True
            elif self.pkg_type in ["python"]:
                likematch = "%python%"
                do_langscan = True
            elif self.pkg_type in ["nuget", "dotnet"]:
                likematch = "%nuget%"
                do_langscan = True
            elif self.pkg_type in ["go"]:
                likematch = "%go%"
                do_langscan = True
            elif self.pkg_type in ["binary"]:
                likematch = "%binary%"
                do_langscan = True
        else:
            do_osscan = True

        if do_langscan:
            semvercount = (
                db.query(FixedArtifact)
                .filter(FixedArtifact.version_format == "semver")
                .count()
            )
            if semvercount:
                nslang = self.pkg_type
                log.debug(
                    "performing LANGPACK vuln scan {} - {}".format(pkgkey, pkgversion)
                )
                if pkgkey and pkgversion and likematch:
                    candidates = (
                        db.query(FixedArtifact)
                        .filter(FixedArtifact.name == pkgkey)
                        .filter(FixedArtifact.version_format == "semver")
                        .filter(FixedArtifact.namespace_name.like(likematch))
                    )
                    for candidate in candidates:
                        if (
                            candidate.vulnerability_id
                            not in [x.vulnerability_id for x in matches]
                        ) and (
                            langpack_compare_versions(
                                candidate.version, pkgversion, language=nslang
                            )
                        ):
                            matches.append(candidate)

        if do_osscan:
            log.debug("performing OS vuln scan {} - {}".format(self.name, self.version))

            dist = DistroNamespace(
                self.distro_name, self.distro_version, self.like_distro
            )
            namespace_name_to_use = dist.namespace_name

            # All options are the same, no need to loop
            if len(set(dist.like_namespace_names)) > 1:
                # Look for exact match first
                if (
                    not db.query(FeedGroupMetadata)
                    .filter(FeedGroupMetadata.name == dist.namespace_name)
                    .first()
                ):
                    # Check all options for distro/flavor mappings, stop at first with records present
                    for namespace_name in dist.like_namespace_names:
                        record_count = (
                            db.query(Vulnerability)
                            .filter(Vulnerability.namespace_name == namespace_name)
                            .count()
                        )
                        if record_count > 0:
                            namespace_name_to_use = namespace_name
                            break

            fix_candidates, vulnerable_candidates = self.candidates_for_package(
                namespace_name_to_use
            )

            for candidate in fix_candidates:
                # De-dup evaluations based on the underlying vulnerability_id. For packages where src has many binary builds, once we have a match we have a match.
                if candidate.vulnerability_id not in [
                    x.vulnerability_id for x in matches
                ] and candidate.match_but_not_fixed(self):
                    matches.append(candidate)

            for candidate in vulnerable_candidates:
                if candidate.vulnerability_id not in [
                    x.vulnerability_id for x in matches
                ] and candidate.match_and_vulnerable(self):
                    matches.append(candidate)

        # log.debug("TIMER DB: {}".format(time.time() - ts))
        return matches

    def candidates_for_package(self, distro_namespace=None):
        """
        Return all vulnerabilities for the named package with the specified distro. Will apply to any version
        of the package. If version is used, will filter to only those for the specified version.

        :param package_obj: the package to match against
        :param distro_namespace: the DistroNamespace object to match against (typically computed
        :return: List of Vulnerabilities
        """
        package_obj = self
        db = get_thread_scoped_session()

        if not distro_namespace:
            namespace_name = DistroNamespace.for_obj(package_obj).namespace_name
        else:
            namespace_name = distro_namespace

        # Match the namespace and package name or src pkg name
        fix_candidates = (
            db.query(FixedArtifact)
            .filter(
                FixedArtifact.namespace_name == namespace_name,
                or_(
                    FixedArtifact.name == package_obj.name,
                    FixedArtifact.name == package_obj.normalized_src_pkg,
                ),
            )
            .all()
        )

        # Match the namespace and package name or src pkg name
        vulnerable_candidates = (
            db.query(VulnerableArtifact)
            .filter(
                VulnerableArtifact.namespace_name == namespace_name,
                or_(
                    VulnerableArtifact.name == package_obj.name,
                    VulnerableArtifact.name == package_obj.normalized_src_pkg,
                ),
            )
            .all()
        )

        return fix_candidates, vulnerable_candidates


class ImagePackageManifestEntry(Base):
    """
    An entry from the package manifest (e.g. rpm, deb, apk) for verifying package contents in a generic way.

    """

    __tablename__ = "image_package_db_entries"

    # Package key
    image_id = Column(String, primary_key=True)
    image_user_id = Column(String, primary_key=True)
    pkg_name = Column(String, primary_key=True)
    pkg_version = Column(String, primary_key=True)
    pkg_type = Column(String, primary_key=True)  # RHEL, DEB, APK, etc.
    pkg_arch = Column(String, default="N/A", primary_key=True)
    pkg_path = Column(String, default="pkgdb", primary_key=True)

    # File path
    file_path = Column(String, primary_key=True)

    is_config_file = Column(Boolean, nullable=True)
    digest = Column(String)  # Will include a prefix: sha256, sha1, md5 etc.
    digest_algorithm = Column(String, nullable=True)
    file_group_name = Column(String, nullable=True)
    file_user_name = Column(String, nullable=True)
    mode = Column(Integer, nullable=True)  # Mode as an integer in decimal, not octal
    size = Column(Integer, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(
                image_id,
                image_user_id,
                pkg_name,
                pkg_version,
                pkg_type,
                pkg_arch,
                pkg_path,
            ),
            refcolumns=(
                "image_packages.image_id",
                "image_packages.image_user_id",
                "image_packages.name",
                "image_packages.version",
                "image_packages.pkg_type",
                "image_packages.arch",
                "image_packages.pkg_path",
            ),
        ),
        {},
    )


NPM_SEQ = Sequence("image_npms_seq_id_seq", metadata=Base.metadata)


class ImageNpm(Base):
    """
    NOTE: This is a deprecated class used for legacy support and upgrade. Image NPMs are now stored in the ImagePackage type
    """

    __tablename__ = "image_npms"

    image_user_id = Column(String, primary_key=True)
    image_id = Column(String, primary_key=True)
    path_hash = Column(String, primary_key=True)  # The sha256 hash of the path in hex
    path = Column(String)
    name = Column(String)
    origins_json = Column(StringJSON)
    source_pkg = Column(String)
    licenses_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    latest = Column(String)
    seq_id = Column(
        Integer, NPM_SEQ, server_default=NPM_SEQ.next_value()
    )  # Note this is not autoincrement as the upgrade code in upgrade.py sets. This table is no longer used as of 0.3.1 and is here for upgrade continuity only.

    image = relationship("Image", back_populates="npms")

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        Index("idx_npm_seq", seq_id),
        {},
    )

    def __repr__(self):
        return "<{} user_id={}, img_id={}, name={}>".format(
            self.__class__, self.image_user_id, self.image_id, self.name
        )


GEM_SEQ = Sequence("image_gems_seq_id_seq", metadata=Base.metadata)


class ImageGem(Base):
    """
    NOTE: This is a deprecated class used for legacy support. Gems are now loaded as types of packages for the ImagePackage class
    """

    __tablename__ = "image_gems"

    image_user_id = Column(String, primary_key=True)
    image_id = Column(String, primary_key=True)
    path_hash = Column(String, primary_key=True)  # The sha256 hash of the path in hex
    path = Column(String)
    name = Column(String)
    files_json = Column(StringJSON)
    origins_json = Column(StringJSON)
    source_pkg = Column(String)
    licenses_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    latest = Column(String)
    seq_id = Column(
        Integer, GEM_SEQ, server_default=GEM_SEQ.next_value()
    )  # This table is no longer used as of 0.3.1 and is here for upgrade continuity only.

    image = relationship("Image", back_populates="gems")

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        Index("idx_gem_seq", seq_id),
        {},
    )

    def __repr__(self):
        return "<{} user_id={}, img_id={}, name={}>".format(
            self.__class__, self.image_user_id, self.image_id, self.name
        )


class ImageCpe(Base):
    __tablename__ = "image_cpes"

    image_user_id = Column(String, primary_key=True)
    image_id = Column(String, primary_key=True)
    pkg_type = Column(String, primary_key=True)  # java, python, gem, npm, etc

    pkg_path = Column(String, primary_key=True)
    cpetype = Column(String, primary_key=True)
    vendor = Column(String, primary_key=True)
    name = Column(String, primary_key=True)
    version = Column(String, primary_key=True)
    update = Column(String, primary_key=True)
    meta = Column(String, primary_key=True)

    image = relationship("Image", back_populates="cpes")

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        Index("ix_image_cpe_user_img", image_id, image_user_id),
        {},
    )

    def __repr__(self):
        return (
            "<{} user_id={}, img_id={}, name={}, version={}, type={}, path={}>".format(
                self.__class__,
                self.image_user_id,
                self.image_id,
                self.name,
                self.version,
                self.pkg_type,
                self.pkg_path,
            )
        )

    def fixed_in(self):
        return None

    def get_cpestring(self):
        ret = None
        try:
            final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
            final_cpe[1] = self.cpetype
            final_cpe[2] = self.vendor
            final_cpe[3] = self.name
            final_cpe[4] = self.version
            final_cpe[5] = self.update
            final_cpe[6] = self.meta
            ret = ":".join(final_cpe)
        except:
            ret = None

        return ret

    def get_cpe23string(self):
        ret = None
        try:
            final_cpe = [
                "cpe",
                "2.3",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
            ]
            final_cpe[2] = self.cpetype
            final_cpe[3] = self.vendor
            final_cpe[4] = self.name
            final_cpe[5] = self.version
            final_cpe[6] = self.update
            final_cpe[7] = self.meta
            # final_cpe[8] = self.language
            # final_cpe[9] = self.sw_edition
            # final_cpe[10] = self.target_sw
            # final_cpe[11] = self.target_hw
            # final_cpe[12] = self.other
            ret = ":".join(final_cpe)
        except:
            ret = None
        return ret

    def get_cpe23_fs_for_sbom(self):
        """
        Returns the formatted string representation of 2.3 CPE for use in sbom constructed for Grype

        A 2.3 CPE is in the format
        cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

        The value '-' for a CPE component means the field is not applicable. Component comparison results in not-equal
        if one CPE has the component set (to value other than * or -) and another CPE indicates the same component is not applicable (-)
        Grype uses all the CPE components for finding a match against the CPEs provided by the vulnerability data.
        Anchore engine does not currently record the last 5 components and thereby defaults them to '-'.
        But that runs the risk of missed matches because of Grype's matching logic as explained above.
        This function is at the other end of the spectrum where it defaults all missing components to the wild character.
        While more matches are found this way, this approach runs the risk of finding false positives.
        Considering the components in play here, there may be a very small chance of such false positives since not many CPEs make use of them
        """
        cpe_components = [
            "cpe",
            "2.3",
            "-",  # part
            "-",  # vendor
            "-",  # product
            "-",  # version
            "-",  # update
            "-",  # edition
            # '*' for all components currently unknown to engine to enable matching in grype.
            "*",  # language
            "*",  # sw_edition
            "*",  # target_sw
            "*",  # target_hw
            "*",  # other
        ]
        cpe_components[2] = self.cpetype
        cpe_components[3] = self.vendor
        cpe_components[4] = self.name
        cpe_components[5] = self.version
        cpe_components[6] = self.update
        cpe_components[7] = self.meta

        return ":".join(cpe_components)


class FilesystemAnalysis(Base):
    """
    A unified and compressed record of the filesystem-level entries in an image. An alternative to the FilesystemItem approach,
    this allows much faster index operations due to a smaller index, but no queries into the content of the filesystems themselves.
    """

    __tablename__ = "image_fs_analysis_dump"

    compression_level = 6
    supported_algorithms = ["gzip"]

    image_id = Column(String, primary_key=True)
    image_user_id = Column(String, primary_key=True)

    compressed_content_hash = Column(String)
    compressed_file_json = Column(LargeBinary, nullable=False)
    total_entry_count = Column(Integer, default=0)
    file_count = Column(Integer, default=0)
    directory_count = Column(Integer, default=0)
    non_packaged_count = Column(Integer, default=0)
    suid_count = Column(Integer, default=0)
    image = relationship("Image", back_populates="fs")
    compression_algorithm = Column(String, default="gzip")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

    image = relationship("Image", back_populates="fs")

    _files = None

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        {},
    )

    # NOTE: operations on the content of the dict itself will not trigger dirty updates and a flush to db,
    # must explicitly set the value to a new dict if writes need to be persisted.

    @property
    def files(self):
        if not self._files:
            self._files = self._files_json()
        return self._files

    @files.setter
    def files(self, value):
        self._files = value
        self._files_from_json(self._files)

    def _files_json(self):
        if self.compression_algorithm == "gzip":
            return json.loads(
                ensure_str(zlib.decompress(ensure_bytes(self.compressed_file_json)))
            )
        else:
            raise ValueError(
                "Got unexpected compresssion algorithm value: {}. Expected {}".format(
                    self.compression_algorithm, self.supported_algorithms
                )
            )

    def _files_from_json(self, file_json):
        """
        Compress and hash the file_json content
        :param file_json:
        :return:
        """
        self.compressed_file_json = zlib.compress(json.dumps(file_json).encode("utf-8"))
        self.compression_algorithm = "gzip"
        self.compressed_content_hash = hashlib.sha256(
            self.compressed_file_json
        ).hexdigest()


class AnalysisArtifact(Base):
    """
    A generic container for an analysis result that doesn't require significant structure.
    Basically wraps a key-value output from a specific analyzer.

    """

    __tablename__ = "image_analysis_artifacts"

    image_id = Column(String, primary_key=True)
    image_user_id = Column(String, primary_key=True)
    analyzer_id = Column(
        String, primary_key=True
    )  # The name of the analyzer (e.g. layer_info)
    analyzer_artifact = Column(
        String, primary_key=True
    )  # The analyzer artifact name (e.g. layers_to_dockerfile)
    analyzer_type = Column(
        String, primary_key=True
    )  # The analyzer type (e.g. base, user, or extra)
    artifact_key = Column(String, primary_key=True)
    str_value = Column(Text)
    json_value = Column(StringJSON)
    binary_value = Column(LargeBinary)
    created_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )
    last_modified = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )

    image = relationship("Image", back_populates="analysis_artifacts")

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(image_id, image_user_id),
            refcolumns=("images.id", "images.user_id"),
        ),
        {},
    )


class Image(Base):
    """
    The core image analysis record. Contains metadata about the image itself.

    """

    __tablename__ = "images"

    id = Column(String, primary_key=True)
    user_id = Column(
        String, primary_key=True
    )  # Images are namespaced in the system to prevent overlap

    state = Column(
        Enum("failed", "initializing", "analyzing", "analyzed", name="image_states"),
        default="initializing",
    )  # For now we only load analyzed images, no progress tracking
    anchore_type = Column(
        Enum(
            "undefined",
            "base",
            "application",
            "user",
            "intermediate",
            name="anchore_image_types",
        ),
        default="undefined",
    )  # TODO: verify if base or undefined should be default

    size = Column(BigInteger)
    created_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )
    last_modified = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )

    digest = Column(String)
    distro_name = Column(String)
    distro_version = Column(String)
    like_distro = Column(String)

    # Should be native JSON, can be handled
    layers_json = Column(StringJSON)
    docker_history_json = Column(StringJSON)
    docker_data_json = Column(StringJSON)
    familytree_json = Column(StringJSON)
    layer_info_json = Column(StringJSON)
    dockerfile_contents = Column(Text)
    dockerfile_mode = Column(String, default="Guessed")

    packages = relationship(
        "ImagePackage",
        back_populates="image",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )
    fs = relationship(
        "FilesystemAnalysis",
        uselist=False,
        lazy="select",
        cascade=["all", "delete", "delete-orphan"],
    )

    # TODO - move these to ImagePackage records instead of individual tables
    gems = relationship(
        "ImageGem",
        back_populates="image",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )
    npms = relationship(
        "ImageNpm",
        back_populates="image",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )

    cpes = relationship(
        "ImageCpe",
        back_populates="image",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )
    analysis_artifacts = relationship(
        "AnalysisArtifact",
        back_populates="image",
        lazy="dynamic",
        cascade=["all", "delete", "delete-orphan"],
    )

    @property
    def distro_namespace(self):
        if self.distro_name and self.distro_version:
            return self.distro_name + ":" + self.distro_version
        else:
            return None

    def distro_namespace_obj(self):
        return DistroNamespace.for_obj(self)

    def get_packages_by_type(self, pkg_type):
        db = get_thread_scoped_session()
        typed_packages = (
            db.query(ImagePackage)
            .filter(
                ImagePackage.image_id == self.id,
                ImagePackage.image_user_id == self.user_id,
                ImagePackage.pkg_type == pkg_type,
            )
            .all()
        )
        return typed_packages

    def vulnerabilities(self):
        """
        Load vulnerabilties for all packages in this image
        :return: list of ImagePackageVulnerabilities
        """
        db = get_thread_scoped_session()
        known_vulnerabilities = (
            db.query(ImagePackageVulnerability)
            .filter(
                ImagePackageVulnerability.pkg_user_id == self.user_id,
                ImagePackageVulnerability.pkg_image_id == self.id,
            )
            .all()
        )
        return known_vulnerabilities

    def cpe_vulnerabilities(self, _nvd_cls, _cpe_cls):
        """
        Similar to the vulnerabilities function, but using the cpe matches instead, basically the NVD raw data source

        :return: list of (image_cpe, cpe_vulnerability) tuples
        """
        db = get_thread_scoped_session()
        if not _nvd_cls or not _cpe_cls:
            _nvd_cls, _cpe_cls = select_nvd_classes(db)
        cpe_vulnerabilities = (
            db.query(ImageCpe, _cpe_cls)
            .filter(
                ImageCpe.image_id == self.id,
                ImageCpe.image_user_id == self.user_id,
                func.lower(ImageCpe.name) == _cpe_cls.name,
                ImageCpe.version == _cpe_cls.version,
            )
            .options(joinedload(_cpe_cls.parent, innerjoin=True))
            .all()
        )

        # vulndb is similar to nvd cpes, add them here
        cpe_vulnerabilities.extend(
            db.query(ImageCpe, VulnDBCpe)
            .filter(
                ImageCpe.image_id == self.id,
                ImageCpe.image_user_id == self.user_id,
                func.lower(ImageCpe.name) == VulnDBCpe.name,
                ImageCpe.version == VulnDBCpe.version,
                VulnDBCpe.is_affected.is_(True),
            )
            .options(joinedload(VulnDBCpe.parent, innerjoin=True))
            .all()
        )

        return cpe_vulnerabilities

    def get_image_base(self):
        """
        Get the image that is this image's base image if it exists. Indicated by first entry of the familytree
        :return: Image object
        """
        base_id = self.familytree_json[0] if self.familytree_json else self
        if base_id == self.id:
            return self
        else:
            db = get_thread_scoped_session()
            return db.query(Image).get((base_id, self.user_id))

    def __repr__(self):
        return "<Image user_id={}, id={}, distro={}, distro_version={}, created_at={}, last_modified={}>".format(
            self.user_id,
            self.id,
            self.distro_name,
            self.distro_version,
            self.created_at,
            self.last_modified,
        )


class ImagePackageVulnerability(Base):
    """
    Provides a mapping between ImagePackage and Vulnerabilities
    """

    __tablename__ = "image_package_vulnerabilities"

    pkg_user_id = Column(String, primary_key=True)
    pkg_image_id = Column(String, primary_key=True)
    pkg_name = Column(String, primary_key=True)
    pkg_version = Column(String, primary_key=True)
    pkg_type = Column(String, primary_key=True)  # RHEL, DEB, APK, etc.
    pkg_arch = Column(String, default="N/A", primary_key=True)

    pkg_path = Column(String, default="pkgdb", primary_key=True)

    vulnerability_id = Column(String, primary_key=True)
    vulnerability_namespace_name = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    package = relationship("ImagePackage", back_populates="vulnerabilities")
    vulnerability = relationship("Vulnerability")

    __table_args__ = (
        ForeignKeyConstraint(
            columns=(
                pkg_image_id,
                pkg_user_id,
                pkg_name,
                pkg_version,
                pkg_type,
                pkg_arch,
                pkg_path,
            ),
            refcolumns=(
                ImagePackage.image_id,
                ImagePackage.image_user_id,
                ImagePackage.name,
                ImagePackage.version,
                ImagePackage.pkg_type,
                ImagePackage.arch,
                ImagePackage.pkg_path,
            ),
        ),
        ForeignKeyConstraint(
            columns=(vulnerability_id, vulnerability_namespace_name),
            refcolumns=(Vulnerability.id, Vulnerability.namespace_name),
        ),
        {},
    )

    def fix_candidates(self) -> list:
        """
        Return the list of FixedArtifact record given a package has been matched to the vulnerability by package/src-package
        name. Does not perform a version check. Will return empty list if no matches

        :return: the name-matched FixedArtifact record list

        """

        if self.vulnerability.fixed_in:
            name_matches = [self.pkg_name, self.package.normalized_src_pkg]
            return [x for x in self.vulnerability.fixed_in if x.name in name_matches]
        return []

    def fixed_artifact(self):
        """
        Return the FixedArtifact record given a package has been matched to the vulnerability

        :return: the matched FixedArtifact record or None if not found
        """

        candidates = self.fix_candidates()
        candidate_count = len(candidates) if candidates else 0
        if candidate_count == 0:
            return None
        elif candidate_count == 1:
            return candidates[0]

        fixed_in = None

        # candidate_count >= 1
        # Do version checks. This package must be affected by the range but not fixed.
        matched = [x for x in candidates if x.match_but_not_fixed(self.package)]

        if len(matched) == 1:
            fixed_in = matched[0]
        elif len(matched) > 1:
            matched.sort(key=lambda x: x.updated_at, reverse=True)
            fixed_in = matched[0]
            # This shouldn't happen since it means there isn't consistency in the data

        return fixed_in

    def fixed_in(self, fixed_in: FixedArtifact = None):
        """
        Return the fixed_in version string value given a package matched (in case there are multiple packages specified in the vuln.

        :return: the fixed in version string if any or None if not found
        """
        if not fixed_in:
            fixed_in = self.fixed_artifact()
        fix_available_in = (
            fixed_in.version if fixed_in and fixed_in.version != "None" else None
        )

        # NOTE: semver version format indicates a range where package
        # is vulnerable (as opposed to a value where anythng < value
        # is vulnerable, and the fix itself is known to exist), so we prepend a 'not' to indicate 'fix is available, if not in semver range'
        if fixed_in and fixed_in.version_format in ["semver"]:
            # Github Advisories can add the real version where there is a fix if any.
            metadata = fixed_in.fix_metadata or {}
            first_patched_version = metadata.get("first_patched_version")
            if first_patched_version:
                return first_patched_version

            if (
                fix_available_in
                and fixed_in.fix_metadata
                and fixed_in.fix_metadata.get("fix_exists", False)
            ):
                fix_available_in = "! {}".format(fix_available_in)
            else:
                fix_available_in = None

        return fix_available_in

    def fix_has_no_advisory(self, fixed_in: FixedArtifact = None):
        """
        For a given package vulnerability match, if the issue won't be addressed by the vendor return True.
        Return False otherwise
        :return:
        """
        if not fixed_in:
            fixed_in = self.fixed_artifact()
        return fixed_in and fixed_in.vendor_no_advisory

    @classmethod
    def from_pair(cls, package_obj, vuln_obj):
        rec = ImagePackageVulnerability()
        rec.pkg_name = package_obj.name
        rec.pkg_type = package_obj.pkg_type
        rec.pkg_arch = package_obj.arch
        rec.pkg_image_id = package_obj.image_id
        rec.pkg_user_id = package_obj.image_user_id
        rec.pkg_version = package_obj.version
        rec.pkg_path = package_obj.pkg_path
        rec.vulnerability_id = (
            vuln_obj.vulnerability_id
            if hasattr(vuln_obj, "vulnerability_id")
            else vuln_obj.id
        )
        rec.vulnerability_namespace_name = vuln_obj.namespace_name
        return rec

    def __repr__(self):
        return "<ImagePackageVulnerability img_user_id={}, img_id={}, pkg_name={}, pkg_version={}, vuln_id={}, vuln_namespace={}, pkg_path={}>".format(
            self.pkg_user_id,
            self.pkg_image_id,
            self.pkg_name,
            self.pkg_version,
            self.vulnerability_id,
            self.vulnerability_namespace_name,
            self.pkg_path,
        )

    # To support hash functions like set operations, ensure these align with primary key comparisons to ensure two identical records would match as such.
    def __eq__(self, other):
        return isinstance(other, type(self)) and (
            self.pkg_user_id,
            self.pkg_image_id,
            self.pkg_name,
            self.pkg_version,
            self.pkg_type,
            self.pkg_arch,
            self.vulnerability_id,
            self.pkg_path,
        ) == (
            other.pkg_user_id,
            other.pkg_image_id,
            other.pkg_name,
            other.pkg_version,
            other.pkg_type,
            other.pkg_arch,
            other.vulnerability_id,
            other.pkg_path,
        )

    def __hash__(self):
        return hash(
            (
                self.pkg_user_id,
                self.pkg_image_id,
                self.pkg_name,
                self.pkg_version,
                self.pkg_type,
                self.pkg_arch,
                self.vulnerability_id,
                self.pkg_path,
            )
        )


class IDistroMapper(object):
    """
    Interface for a distro mapper object
    """

    def __init__(self, distro, version, like_distro, found_mapping):
        self.from_distro = distro
        self.from_version = version
        self.from_like_distro = like_distro
        self.found_mapping = found_mapping
        self.mapping = self._do_mapping()

    def _do_mapping(self):
        """
        Map from the given values to a new distro if an explicit mapping exists or else None

        :param distro_name:
        :param distro_version:
        :param like_distro:
        :return: list of tuples: [(distro, version, flavor), ... ,(distro, versionN, flavorN)]
        """
        pass

    def _map_name(self, distro_name, distro_version, like_distro, found_mapping=None):
        pass

    def _map_version(
        self, distro_name, distro_version, like_distro, found_mapping=None
    ):
        pass

    def _map_flavor(self, distro_name, distro_version, like_distro, found_mapping=None):
        pass


class VersionPreservingDistroMapper(IDistroMapper):
    def _do_mapping(self):
        """
        Map from the given values to a new distro if an explicit mapping exists or else None

        :param distro_name:
        :param distro_version:
        :param like_distro:
        :return: list of tuples: [(distro, version, flavor), ... ,(distro, versionN, flavorN)]
        """

        distro = None
        versions = None
        flavor = None

        try:
            distro = self._map_name(
                self.from_distro,
                self.from_version,
                self.from_like_distro,
                self.found_mapping,
            )
            flavor = self._map_flavor(
                self.from_distro,
                self.from_version,
                self.from_like_distro,
                self.found_mapping,
            )
            versions = self._map_version(
                self.from_distro,
                self.from_version,
                self.from_like_distro,
                self.found_mapping,
            )
            return [
                DistroTuple(distro=distro, version=v, flavor=flavor) for v in versions
            ]
        except:
            log.exception(
                "Failed to fully construct the mapped distro from: {}, {}, {}".format(
                    self.from_distro, self.from_version, self.from_like_distro
                )
            )
            raise

    def _map_name(self, distro_name, distro_version, like_distro, found_mapping=None):
        if found_mapping:
            return found_mapping.to_distro
        else:
            return distro_name

    def _map_flavor(self, distro_name, distro_version, like_distro, found_mapping=None):
        if found_mapping:
            return found_mapping.flavor
        else:
            db = get_thread_scoped_session()
            candidates = like_distro.split(",") if like_distro else []
            for c in candidates:
                mapping = db.query(DistroMapping).get(c)
                if mapping:
                    return mapping.flavor
            return None

    def _map_version(
        self, distro_name, distro_version, like_distro, found_mapping=None
    ):
        """
        Maps version into a list of versions ordered by closeness of match: [full original version, major.minor]
        Only provides the second, major/minor, mapping if the version matches a dot delimited digit sequence

        :param distro_name:
        :param distro_version:
        :param like_distro:
        :param found_mapping:
        :return:
        """

        # Parse down to major, minor only if has a subminor
        patt = re.match(r"(\d+)\.(\d+)\.(\d+)", distro_version)
        if patt:
            major, minor, subminor = patt.groups()
            return [distro_version, "{}.{}".format(major, minor), "{}".format(major)]

        # Parse dow to only major
        patt = re.match(r"(\d+)\.(\d+)", distro_version)
        if patt:
            major, minor = patt.groups()
            return [distro_version, "{}.{}".format(major, minor), "{}".format(major)]

        return [distro_version]


class DistroMapping(Base):
    """
    A mapping entry between a distro with known cve feed and other similar distros.
    Used to explicitly map similar distros to a base feed for cve matches.
    """

    __tablename__ = "distro_mappings"
    __distro_mapper_cls__ = VersionPreservingDistroMapper

    from_distro = Column(String, primary_key=True)  # The distro to be checked
    to_distro = Column(
        String
    )  # The distro to use instead of the pk distro to do cve checks
    flavor = Column(String)  # The distro flavor to use (e.g. RHEL, or DEB)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    @classmethod
    def distros_for(cls, distro, version, like_distro=""):
        """
        Returns a pair of mappings for the given object assuming the object has distro_name and distro_version and like_distro
        fields. First element of the pair is the exact distro namespace, the second is either None or a like-relation mapping
         using the to_distro value of the found mapping.

        :param obj:
        :return: list of DistroTuples for most-to-least exact match
        """
        db = get_thread_scoped_session()
        found = db.query(DistroMapping).get(distro)
        mapper = cls.__distro_mapper_cls__(distro, version, like_distro, found)
        return mapper.mapping

    @classmethod
    def distros_mapped_to(cls, distro, version):
        """
        Reverse of distros_for, returns the list of namespace names that would map to the given distro and version.

        :param distro:
        :param version:
        :return:
        """
        db = get_thread_scoped_session()
        name_matches = (
            db.query(DistroMapping).filter(DistroMapping.to_distro == distro).all()
        )
        return [
            DistroTuple(
                distro=mapping.from_distro, version=version, flavor=mapping.flavor
            )
            for mapping in name_matches
        ]

    def __str__(self):
        return "<DistroMapping>from={} to={}, flavor={}".format(
            self.from_distro, self.to_distro, self.flavor
        )


class DistroNamespace(object):
    """
    A helper object for holding and converting distro names and namespaces between image and vulnerability records.
    Abstracts the conversion of name, version, like_version sets into usable strings for comparing and matching records.

    The 'like' relation defines similar pkg types and cve feed sources. If distro A is like distro B, then distro A should be able to match
    against distro B's vulnerability feeds.

    """

    @classmethod
    def for_obj(cls, obj):
        if hasattr(obj, "distro_name") and hasattr(obj, "distro_version"):
            return DistroNamespace(
                getattr(obj, "distro_name"),
                getattr(obj, "distro_version"),
                like_distro=getattr(obj, "like_distro", None),
            )
        else:
            raise TypeError(
                "Given object must have attributes: distro_name, distro_version"
            )

    def __init__(self, name="UNKNOWN", version="UNKNOWN", like_distro=None):
        self.name = name
        self.version = version
        self.like_distro = like_distro
        self.mapping = DistroMapping.distros_for(
            self.name, self.version, self.like_distro
        )
        self.flavor = self.mapping[0].flavor if self.mapping else "Unknown"
        self.namespace_name = DistroNamespace.as_namespace_name(
            self.mapping[0].distro, self.mapping[0].version
        )
        self.like_namespace_names = [
            DistroNamespace.as_namespace_name(x.distro, x.version) for x in self.mapping
        ]

    @staticmethod
    def as_namespace_name(name, version):
        """
        Direct conversion to a single namespace name. Does not follow any 'like' relations.

        :return:
        """
        return name + ":" + version

    def mapped_names(self):
        """
        Return the list of namespaces that can map to this one. Only returns distro names who's DistroMapping relation is the exact
        name of this object's name field. Ensures that only direct mappings are returned, and avoids intermediate names being mapped
        as related to each other when they simply share a parent.

        E.g.

        ol like centos,
        fedora like centos,
        fedora not like ol
        ol not like fedora

        :return: list of name, version pairs
        """
        return [
            x.distro for x in DistroMapping.distros_mapped_to(self.name, self.version)
        ]


class StorageInterface(object):
    """
    Interface for a stored object in policy engine stored in persistence. Expects a member/column called result in the implementation
    """

    def _constuct_raw_result(self, result_json):
        return {"type": "direct", "result": result_json}

    def _construct_remote_result(self, bucket, key, digest):
        """
        Build the result json for the db record

        :param bucket: bucket in archive to lookup result
        :param key: key in archive to lookup result
        :param digest: sha256 digest of the result
        :return:
        """
        return {
            "type": "archive",
            "digest": digest,
            "uri": "catalog://{bucket}/{key}".format(bucket=bucket, key=key),
        }

    def add_raw_result(self, result_json):
        self.result = self._constuct_raw_result(result_json)

    def add_remote_result(self, bucket, key, result_digest):
        self.result = self._construct_remote_result(bucket, key, result_digest)

    def is_raw(self):
        return self.result["type"] == "direct"

    def is_archive_ref(self):
        return self.result["type"] == "archive"

    def archive_tuple(self):
        """
        Returns the bucket, key tuple for an archive reference
        :return:
        """

        if self.is_archive_ref():
            uri = self.result.get("uri", "")
            _, path = uri.split("catalog://", 1)
            bucket, key = path.split("/", 1)
            return bucket, key
        else:
            raise ValueError("Result type is not an archive")


class ImageVulnerabilitiesReport(Base, StorageInterface):
    __tablename__ = "image_vulnerabilities_reports"

    account_id = Column(String, primary_key=True)
    image_digest = Column(String, primary_key=True)
    report_key = Column(String, index=True)
    generated_at = Column(DateTime, index=True)
    result = Column(JSONB)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_modified = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
    )


class CachedPolicyEvaluation(Base, StorageInterface):
    __tablename__ = "policy_engine_evaluation_cache"

    user_id = Column(String, primary_key=True)
    image_id = Column(String, primary_key=True)
    eval_tag = Column(String, primary_key=True)
    bundle_id = Column(
        String, primary_key=True
    )  # Need both id and digest to differentiate a new bundle vs update to bundle that requires a flush of the old record
    bundle_digest = Column(String, primary_key=True)

    result = Column(
        StringJSON, nullable=False
    )  # Result struct, based on the 'type' inside, may be literal content or a reference to the archive

    created_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )
    last_modified = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow,
        nullable=False,
    )

    def key_tuple(self):
        return (
            self.user_id,
            self.image_id,
            self.eval_tag,
            self.bundle_id,
            self.bundle_digest,
        )


def select_nvd_classes(db=None):
    if not db:
        db = get_thread_scoped_session()

    _nvd_cls = NvdMetadata
    _cpe_cls = CpeVulnerability
    try:
        fmd = db.query(FeedMetadata).filter(FeedMetadata.name == "nvdv2").first()
        if fmd and fmd.last_full_sync:
            _nvd_cls = NvdV2Metadata
            _cpe_cls = CpeV2Vulnerability
    except Exception as err:
        log.warn("could not query for nvdv2 sync: {}".format(err))

    log.debug("selected {}/{} nvd classes".format(_nvd_cls, _cpe_cls))
    return _nvd_cls, _cpe_cls


def _get_one_or_none(key, val, collection):
    """
    Find a match for the object in the collection using the key-value pair,
    return the result only if 1 match is found.

    Example instance of collection
    [
        {
          "source": "CVE ID",
          "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2000-0089"
        },
        {
          "source": "Bugtraq ID",
          "url": "http://www.securityfocus.com/bid/947"
        },
    ]
    """
    if not key or not val:
        return None
    result = None

    for entry in collection:
        if entry.get(key) == val:
            if result:
                return None
            else:
                result = entry
    return result
