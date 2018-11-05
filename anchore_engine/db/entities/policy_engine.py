import datetime
import hashlib
import json
import re
import time
import zlib
from collections import namedtuple

from sqlalchemy import Column, BigInteger, Integer, LargeBinary, Float, Boolean, String, ForeignKey, Enum, \
    ForeignKeyConstraint, DateTime, types, Text, Index, JSON, or_, and_
from sqlalchemy.orm import relationship

from anchore_engine.utils import ensure_str, ensure_bytes

from anchore_engine.util.rpm import compare_versions as rpm_compare_versions
from anchore_engine.util.deb import compare_versions as dpkg_compare_versions
from anchore_engine.util.apk import compare_versions as apkg_compare_versions
from anchore_engine.util.langpack import compare_versions as langpack_compare_versions, langpack_is_all

try:
    from anchore_engine.subsys import logger as log
except:
    import logging
    logger = logging.getLogger(__name__)
    log = logger

from .common import Base, UtilMixin, StringJSON
from .common import get_thread_scoped_session


# String field lengths for consistency across entities
user_id_length = 64
digest_length = 64 + 10  # pad for the method type, e.g. sha256: or md5:
image_id_length = 80
namespace_length = 64
namespace_version_length = 32
distro_length = 64
distro_version_length = 64
feed_record_id_length = 128
feed_name_length = 64
feed_group_length = 64
vuln_id_length = feed_record_id_length
pkg_name_length = 255
pkg_version_length = 128
pkg_type_length = 32
link_length = 1024
tag_length = 64
registry_length = 255
repository_length = 255
fulltag_length = 255
bundle_id_length = 128
file_path_length = 512
hash_length = 80

DistroTuple = namedtuple('DistroTuple', ['distro', 'version', 'flavor'])

# Feeds
class FeedMetadata(Base, UtilMixin):
    __tablename__ = 'feeds'

    name = Column(String(feed_name_length), primary_key=True)
    description = Column(String(512))
    access_tier = Column(Integer)
    groups = relationship('FeedGroupMetadata', back_populates='feed')
    last_full_sync = Column(DateTime)
    last_update = Column(DateTime)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    @classmethod
    def get_by_name(cls, name):
        return FeedMetadata.query.filter(name=name).scalar()

    def __repr__(self):
        return '<{}(name={}, access_tier={}, created_at={}>'.format(self.__class__, self.name, self.access_tier, self.created_at.isoformat())


class FeedGroupMetadata(Base, UtilMixin):
    __tablename__ = 'feed_groups'

    name = Column(String(feed_group_length), primary_key=True)
    feed_name = Column(String(feed_name_length), ForeignKey(FeedMetadata.name), primary_key=True)
    description = Column(String(512))
    access_tier = Column(Integer)
    last_sync = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    feed = relationship('FeedMetadata', back_populates='groups')

    def __repr__(self):
        return '<{} name={}, feed={}, access_tier={}, created_at={}>'.format(self.__class__, self.name, self.feed_name, self.access_tier,
                                                                              self.created_at)


class GenericFeedDataRecord(Base):
    """
    A catch-all record for feed data without a specific schema mapping
    """
    __tablename__ = 'feed_group_data'

    feed = Column(String(feed_name_length), primary_key=True)
    group = Column(String(feed_group_length), primary_key=True)
    id = Column(String(feed_record_id_length), primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    data = Column(StringJSON, nullable=False) # TODO: make this a JSON type for dbs that support it


class GemMetadata(Base):
    __tablename__ = 'feed_data_gem_packages'

    name = Column(String(pkg_name_length), primary_key=True)
    id = Column(BigInteger)
    latest = Column(String(pkg_version_length))
    licenses_json = Column(StringJSON)
    authors_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # TODO: make these server-side
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def __repr__(self):
        return '<{} name={}, id={}, created_at={}>'.format(self.__class__, self.name, self.id,
                                                                              self.created_at)

    def key_tuple(self):
        return self.name


class NpmMetadata(Base):
    __tablename__ = 'feed_data_npm_packages'

    name = Column(String(pkg_name_length), primary_key=True)
    sourcepkg = Column(String(pkg_name_length))
    lics_json = Column(StringJSON)
    origins_json = Column(StringJSON)
    latest = Column(String(pkg_name_length))
    versions_json = Column(StringJSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # TODO: make these server-side
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def __repr__(self):
        return '<{} name={}, sourcepkg={}, created_at={}>'.format(self.__class__, self.name, self.sourcepkg,
                                                                              self.created_at.isoformat())

    def key_tuple(self):
        return self.name


class Vulnerability(Base):
    """
    A vulnerability/CVE record. Can come from many sources. Includes some specific fields and also a general
    metadata field that is json encoded string
    """

    __tablename__ = 'feed_data_vulnerabilities'

    id = Column(String(vuln_id_length), primary_key=True)  # CVE Id, RHSA id, etc
    namespace_name = Column(String(namespace_length), primary_key=True)  # e.g. centos, rhel, "debian"
    severity = Column(Enum('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', name='vulnerability_severities'), nullable=False)
    description = Column(Text, nullable=True)
    link = Column(String(link_length), nullable=True)
    metadata_json = Column(StringJSON, nullable=True)
    cvss2_vectors = Column(String(256), nullable=True)
    cvss2_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # TODO: make these server-side
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    vulnerable_in = relationship('VulnerableArtifact', back_populates='parent', cascade='all, delete-orphan')
    fixed_in = relationship('FixedArtifact', back_populates='parent', cascade='all, delete-orphan')


    @property
    def additional_metadata(self):
        if self.metadata_json:
            if isinstance(self.metadata_json, str):
                return(json.loads(self.metadata_json))
            return(self.metadata_json)
        return(None)
        #if self.metadata_json:
        #    return json.loads(self.metadata_json)
        #else:
        #    return None

    @additional_metadata.setter
    def additional_metadata(self, value):
        m = {}
        if value:
            if isinstance(value, str):
                m = json.loads(value)
            elif isinstance(value, dict):
                m.update(value)
            else:
                m = {'metadata': value}
        self.metadata_json = m
        #self.metadata_json = json.dumps(value)

    def __repr__(self):
        return '<{} id={}, namespace_name={}, severity={}, created_at={}>'.format(self.__class__, self.id, self.namespace_name, self.severity,
                                                                          self.created_at)
    def current_package_vulnerabilities(self, db_session):
        """
        Return a list of all packages that are marked as vulnerable to this item
        :return: list of ImagePackageVulnerability objects
        """
        return db_session.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_id == self.id, ImagePackageVulnerability.vulnerability_namespace_name == self.namespace_name).all()

    def is_empty(self):
        """
        Can a package be vulnerable to this, or is it an empty definition.
        :return: boolean
        """
        #return not self.vulnerable_in and not self.fixed_in
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
        return(sev)


class VulnerableArtifact(Base):
    """
    An entity affected by a vulnerability, typically an os or application package.
    Typically populated by CVEs with specific vulnerable packages enumerated.

    """
    __tablename__ = 'feed_data_vulnerabilities_vulnerable_artifacts'

    vulnerability_id = Column(String(vuln_id_length), primary_key=True)
    namespace_name = Column(String(namespace_length), primary_key=True)
    name = Column(String(pkg_name_length), primary_key=True)
    version = Column(String(pkg_version_length), primary_key=True)
    version_format = Column(String(pkg_type_length))
    epochless_version = Column(String(pkg_version_length))
    include_previous_versions = Column(Boolean, default=True)
    parent = relationship('Vulnerability', back_populates='vulnerable_in')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (ForeignKeyConstraint(columns=[vulnerability_id, namespace_name],
                                           refcolumns=[Vulnerability.id, Vulnerability.namespace_name]), {})

    def __repr__(self):
        return '<{} name={}, version={}, vulnerability_id={}, namespace_name={}, created_at={}>'.format(self.__class__, self.name, self.version, self.vulnerability_id, self.namespace_name,
                                                                          self.updated_at)

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
            raise TypeError('Expected a VulnerableArtifact type, got: {}'.format(type(vuln_obj)))

        dist = DistroNamespace.for_obj(package_obj)
        flavor = dist.flavor

        # Double-check names
        if vuln_obj.name != package_obj.name and vuln_obj.name != package_obj.normalized_src_pkg:
            log.warn(
                'Name mismatch in vulnerable check. This should not happen: Fix: {}, Package: {}, Package_Norm_Src: {}, Package_Src: {}'.format(
                    vuln_obj.name, package_obj.name, package_obj.normalized_src_pkg, package_obj.src_pkg))
            return False

        # Is it a catch-all record? Explicit 'None' or 'all' versions indicate all versions of the named package are vulnerable.
        if vuln_obj.epochless_version in ['all', 'None']:
            return True

        # Is the package older than the fix?
        if package_obj.fullversion == vuln_obj.epochless_version or package_obj.version == vuln_obj.epochless_version:
            return True

        # Newer or the same
        return False

class FixedArtifact(Base):
    """
    A record indicating an artifact version that marks a fix for a vulnerability
    """
    __tablename__ = 'feed_data_vulnerabilities_fixed_artifacts'

    vulnerability_id = Column(String(vuln_id_length), primary_key=True)
    namespace_name = Column(String(namespace_length), primary_key=True)
    name = Column(String(pkg_name_length), primary_key=True)
    version = Column(String(pkg_version_length), primary_key=True)
    version_format = Column(String(pkg_type_length))
    epochless_version = Column(String(pkg_version_length))
    include_later_versions = Column(Boolean, default=True)
    parent = relationship('Vulnerability', back_populates='fixed_in')
    vendor_no_advisory = Column(Boolean, default=False)
    fix_metadata = Column(StringJSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    __table_args__ = (ForeignKeyConstraint(columns=[vulnerability_id, namespace_name],
                                           refcolumns=[Vulnerability.id, Vulnerability.namespace_name]), {})

    def __repr__(self):
        return '<{} name={}, version={}, vulnerability_id={}, namespace_name={}, created_at={}>'.format(self.__class__, self.name, self.version, self.vulnerability_id, self.namespace_name, self.created_at)

    def match_but_not_fixed(self, package_obj):
        """
        Does the FixedArtifact match the package as a vulnerability such that the fix indicates the package is *not* fixed and is
        therefore vulnerable.

        :param fix_obj: as FixedArtifact record
        :param package_obj: an ImagePackage record
        :return: True if the names match and the fix record indicates the package is vulnerable and not fixed. False if no match or fix is applied and no vulnerability match
        """
        fix_obj  = self
        if not isinstance(fix_obj, FixedArtifact):
            raise TypeError('Expected a FixedArtifact type, got: {}'.format(type(fix_obj)))

        dist = DistroNamespace.for_obj(package_obj)
        flavor = dist.flavor
        log.spew('Package: {}, Fix: {}, Flavor: {}'.format(package_obj.name, fix_obj.name, flavor))

        # Double-check names
        if fix_obj.name != package_obj.name and fix_obj.name != package_obj.normalized_src_pkg:
            log.warn('Name mismatch in fix check. This should not happen: Fix: {}, Package: {}, Package_Norm_Src: {}, Package_Src: {}'.format(fix_obj.name, package_obj.name, package_obj.normalized_src_pkg, package_obj.src_pkg))
            return False

        # Handle the case where there is no version, indicating no fix available, all versions are vulnerable.
        # Is it a catch-all record? Explicit 'None' versions indicate all versions of the named package are vulnerable.
        if fix_obj.version == 'None':
            return True

        # Is the package older than the fix?
        if flavor == 'RHEL':
            if rpm_compare_versions(package_obj.name, package_obj.fullversion, fix_obj.name, fix_obj.epochless_version) < 0:
                log.spew('rpm Compared: {} < {}: True'.format(package_obj.fullversion, fix_obj.epochless_version))
                return True
        elif flavor == 'DEB':
            if dpkg_compare_versions(package_obj.fullversion, 'lt', fix_obj.epochless_version):
                log.spew('dpkg Compared: {} < {}: True'.format(package_obj.fullversion, fix_obj.epochless_version))
                return True
        elif flavor == 'ALPINE':
            if apkg_compare_versions(package_obj.fullversion, 'lt', fix_obj.epochless_version):
                log.spew('apkg Compared: {} < {}: True'.format(package_obj.fullversion, fix_obj.epochless_version))
                return True


        if package_obj.pkg_type in ['java', 'maven', 'npm', 'gem', 'python', 'js']:
            if package_obj.pkg_type in ['java', 'maven']:
                pomprops = package_obj.get_pom_properties()
                if pomprops:
                    pkgkey = "{}:{}".format(pomprops.get('groupId'), pomprops.get('artifactId'))
                    pkgversion = pomprops.get('version', None)
                else:
                    pkgversion = package_obj.version
            else:
                pkgversion = package_obj.fullversion

            if langpack_compare_versions(fix_obj.version, pkgversion, language=package_obj.pkg_type):
                return(True)

        # Newer or the same
        return False


class NvdMetadata(Base):
    __tablename__ = 'feed_data_nvd_vulnerabilities'

    name = Column(String(vuln_id_length), primary_key=True)
    namespace_name = Column(String(namespace_length), primary_key=True)  # e.g. nvddb:2018"
    severity = Column(Enum('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', name='vulnerability_severities'), nullable=False, primary_key=True)
    vulnerable_configuration = Column(StringJSON)
    vulnerable_software = Column(StringJSON)
    summary = Column(String)
    cvss = Column(StringJSON)
    vulnerable_cpes = relationship('CpeVulnerability', back_populates='parent', cascade='all, delete-orphan')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # TODO: make these server-side
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def __repr__(self):
        return '<{} name={}, created_at={}>'.format(self.__class__, self.name, self.created_at)

    def get_severity(self):
        sev = "Unknown"
        try:
            cvss_json = json.loads(self.cvss)
            score = float(cvss_json['base_metrics']['score'])
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
        return(sev)

    def key_tuple(self):
        return self.name


class CpeVulnerability(Base):
    __tablename__ = 'feed_data_cpe_vulnerabilities'

    feed_name = Column(String(feed_name_length), primary_key=True)
    namespace_name = Column(String(namespace_length), primary_key=True)
    vulnerability_id = Column(String(vuln_id_length), primary_key=True)
    severity = Column(Enum('Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical', name='vulnerability_severities'), nullable=False, primary_key=True)
    cpetype = Column(String(pkg_name_length), primary_key=True)
    vendor = Column(String(pkg_name_length), primary_key=True)
    name = Column(String(pkg_name_length), primary_key=True)
    version = Column(String(pkg_version_length), primary_key=True)
    update = Column(String(pkg_version_length), primary_key=True)
    meta = Column(String(pkg_name_length), primary_key=True)
    link = Column(String(link_length), nullable=True)
    parent = relationship('NvdMetadata', back_populates='vulnerable_cpes')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)  # TODO: make these server-side
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # This is necessary for ensuring correct FK behavior against a composite foreign key
    __table_args__ = (
        ForeignKeyConstraint(columns=[vulnerability_id, namespace_name, severity], refcolumns=[NvdMetadata.name, NvdMetadata.namespace_name, NvdMetadata.severity]),
        #Index('ix_feed_data_cpe_vulnerabilities_name_version', name, version),
        {}
    )

    def __repr__(self):
        return '<{} feed_name={}, vulnerability_id={}, name={}, version={}, created_at={}>'.format(self.__class__, self.feed_name, self.vulnerability_id, self.name, self.version, self.created_at.isoformat())

    def get_cpestring(self):
        ret = None
        try:
            final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
            final_cpe[1] = self.cpetype
            final_cpe[2] = self.vendor
            final_cpe[3] = self.name
            final_cpe[4] = self.version
            final_cpe[5] = self.update
            final_cpe[6] = self.meta
            ret = ':'.join(final_cpe)
        except:
            ret = None

        return(ret)


# Analysis Data for Images

class ImagePackage(Base):
    """
    A package detected in an image by analysis
    """
    __tablename__ = 'image_packages'

    image_id = Column(String(image_id_length), primary_key=True)
    image_user_id = Column(String(user_id_length), primary_key=True)

    name = Column(String(pkg_name_length), primary_key=True)
    version = Column(String(pkg_version_length), primary_key=True)
    pkg_type = Column(String(pkg_type_length), primary_key=True)  # RHEL, DEB, APK, etc.
    arch = Column(String(16), default='N/A', primary_key=True)
    pkg_path = Column(String(file_path_length), default='pkgdb', primary_key=True)

    pkg_path_hash = Column(String(hash_length))  # The sha256 hash of the path in hex

    # Could pkg namespace be diff than os? e.g. rpms in Deb?
    distro_name = Column(String(distro_length))
    distro_version = Column(String(distro_version_length))
    like_distro = Column(String(distro_length))

    fullversion = Column(String(pkg_version_length))
    release = Column(String(pkg_version_length), default='')
    origin = Column(String(512), default='N/A')
    src_pkg = Column(String(pkg_name_length + pkg_version_length), default='N/A')
    normalized_src_pkg = Column(String(pkg_name_length + pkg_version_length), default='N/A')

    metadata_json = Column(StringJSON)

    license = Column(String(1024), default='N/A')
    size = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    vulnerabilities = relationship('ImagePackageVulnerability', back_populates='package', lazy='dynamic')
    image = relationship('Image', back_populates='packages')
    pkg_db_entries = relationship('ImagePackageManifestEntry', backref='package', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id', 'images.user_id']),
                             Index('ix_image_package_distronamespace', name, version, distro_name, distro_version, normalized_src_pkg),
        {}
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
            return self.distro_name + ':' + self.distro_version
        else:
            return None

    def get_pom_properties(self):
        if not self.metadata_json:
            return None

        filebuf = self.metadata_json.get('pom.properties', "")
        props = {}
        for line in filebuf.splitlines():
            #line = anchore_engine.utils.ensure_str(line)
            if not re.match("\s*(#.*)?$", line):
                kv = line.split('=')
                key = kv[0].strip()
                value = '='.join(kv[1:]).strip()
                props[key] = value
        return props

    def vulnerabilities_for_package(self):
        """
        Given an ImagePackage object, return the vulnerabilities that it matches.

        :param package_obj:
        :return: list of Vulnerability objects
        """
        #ts = time.time()

        #package_obj = self
        log.debug('Finding vulnerabilities for package: {} - {}'.format(self.name, self.version))

        matches = []
        db = get_thread_scoped_session()

        # decide what type of scan(s) to perform
        do_langscan = do_osscan = False

        pkgkey = pkgversion = None
        likematch = None
        if self.pkg_type in ['java', 'maven']:
            # search for maven hits
            if self.metadata_json:
                pombuf = self.metadata_json.get('pom.properties', "")
                if pombuf:
                    pomprops = self.get_pom_properties()
                    pkgkey = "{}:{}".format(pomprops.get('groupId'), pomprops.get('artifactId'))
                    pkgversion = pomprops.get('version', None)
                    likematch = '%java%'
                    do_langscan = True

        elif self.pkg_type in ['ruby', 'gem', 'npm', 'js', 'python']:
            pkgkey = self.name
            pkgversion = self.version
            if self.pkg_type in ['ruby', 'gem']:
                likematch = '%ruby%'
                do_langscan = True
            elif self.pkg_type in ['npm', 'js']:
                likematch = '%js%'
                do_langscan = True
            elif self.pkg_type in ['python']:
                likematch = '%python%'
                do_langscan = True
        else:
            do_osscan = True

        if do_langscan:
            semvercount = db.query(FixedArtifact).filter(FixedArtifact.version_format == 'semver').count()
            if semvercount:
                nslang = self.pkg_type
                log.debug("performing LANGPACK vuln scan {} - {}".format(pkgkey, pkgversion))
                if pkgkey and pkgversion and likematch:
                    candidates = db.query(FixedArtifact).filter(FixedArtifact.name == pkgkey).filter(FixedArtifact.version_format == 'semver').filter(FixedArtifact.namespace_name.like(likematch))
                    for candidate in candidates:
                        if (candidate.vulnerability_id not in [x.vulnerability_id for x in matches]) and (langpack_compare_versions(candidate.version, pkgversion, language=nslang)):
                            matches.append(candidate)

        if do_osscan:
            log.debug("performing OS vuln scan {} - {}".format(self.name, self.version))

            dist = DistroNamespace(self.distro_name, self.distro_version, self.like_distro)
            namespace_name_to_use = dist.namespace_name

            # All options are the same, no need to loop
            if len(set(dist.like_namespace_names)) > 1:
                # Look for exact match first
                if not db.query(FeedGroupMetadata).filter(FeedGroupMetadata.name == dist.namespace_name).first():
                    # Check all options for distro/flavor mappings, stop at first with records present
                    for namespace_name in dist.like_namespace_names:
                        record_count = db.query(Vulnerability).filter(Vulnerability.namespace_name == namespace_name).count()
                        if record_count > 0:
                            namespace_name_to_use = namespace_name
                            break

            fix_candidates, vulnerable_candidates = self.candidates_for_package(namespace_name_to_use)

            for candidate in fix_candidates:
                # De-dup evaluations based on the underlying vulnerability_id. For packages where src has many binary builds, once we have a match we have a match.
                if candidate.vulnerability_id not in [x.vulnerability_id for x in matches] and candidate.match_but_not_fixed(self):
                    matches.append(candidate)

        #for candidate in vulnerable_candidates:
        #    if candidate.vulnerability_id not in [x.vulnerability_id for x in matches] and candidate.match_and_vulnerable(package_obj):
        #        matches.append(candidate)

        #log.debug("TIMER DB: {}".format(time.time() - ts))
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
        fix_candidates = db.query(FixedArtifact).filter(FixedArtifact.namespace_name == namespace_name,
                                                            or_(FixedArtifact.name == package_obj.name, FixedArtifact.name == package_obj.normalized_src_pkg)).all()

        # Match the namespace and package name or src pkg name
        vulnerable_candidates = []
        #vulnerable_candidates = db.query(VulnerableArtifact).filter(VulnerableArtifact.namespace_name == namespace_name,
        #                                                            or_(VulnerableArtifact.name == package_obj.name, VulnerableArtifact.name == package_obj.normalized_src_pkg)).all()


        return fix_candidates, vulnerable_candidates

class ImagePackageManifestEntry(Base):
    """
    An entry from the package manifest (e.g. rpm, deb, apk) for verifying package contents in a generic way.

    """
    __tablename__ = 'image_package_db_entries'

    # Package key
    image_id = Column(String(image_id_length), primary_key=True)
    image_user_id = Column(String(user_id_length), primary_key=True)
    pkg_name = Column(String(pkg_name_length), primary_key=True)
    pkg_version = Column(String(pkg_version_length), primary_key=True)
    pkg_type = Column(String(pkg_type_length), primary_key=True)  # RHEL, DEB, APK, etc.
    pkg_arch = Column(String(16), default='N/A', primary_key=True)
    pkg_path = Column(String(file_path_length), default='pkgdb', primary_key=True)

    # File path
    file_path = Column(String(file_path_length), primary_key=True)

    is_config_file = Column(Boolean, nullable=True)
    digest = Column(String(digest_length)) # Will include a prefix: sha256, sha1, md5 etc.
    digest_algorithm = Column(String(8), nullable=True)
    file_group_name = Column(String, nullable=True)
    file_user_name = Column(String, nullable=True)
    mode = Column(Integer, nullable=True) # Mode as an integer in decimal, not octal
    size = Column(Integer, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path],
                             refcolumns=['image_packages.image_id', 'image_packages.image_user_id', 'image_packages.name', 'image_packages.version', 'image_packages.pkg_type', 'image_packages.arch', 'image_packages.pkg_path']),
        {}
    )


class ImageNpm(Base):
    __tablename__ = 'image_npms'

    image_user_id = Column(String(user_id_length), primary_key=True)
    image_id = Column(String(image_id_length), primary_key=True)
    path_hash = Column(String(hash_length), primary_key=True)  # The sha256 hash of the path in hex
    path = Column(String(file_path_length))
    name = Column(String(pkg_name_length))
    origins_json = Column(StringJSON)
    source_pkg = Column(String(pkg_name_length))
    licenses_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    latest = Column(String(pkg_version_length))

    image = relationship('Image', back_populates='npms')

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id','images.user_id']),
        {}
    )

    def __repr__(self):
        return '<{} user_id={}, img_id={}, name={}>'.format(self.__class__, self.image_user_id, self.image_id, self.name)


class ImageGem(Base):
    __tablename__ = 'image_gems'

    image_user_id = Column(String(user_id_length), primary_key=True)
    image_id = Column(String(image_id_length), primary_key=True)
    path_hash = Column(String(hash_length), primary_key=True)  # The sha256 hash of the path in hex
    path = Column(String(file_path_length))
    name = Column(String(pkg_name_length))
    files_json = Column(StringJSON)
    origins_json = Column(StringJSON)
    source_pkg = Column(String(pkg_name_length))
    licenses_json = Column(StringJSON)
    versions_json = Column(StringJSON)
    latest = Column(String(pkg_version_length))

    image = relationship('Image', back_populates='gems')

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id', 'images.user_id']),
        {}
    )

    def __repr__(self):
        return '<{} user_id={}, img_id={}, name={}>'.format(self.__class__, self.image_user_id, self.image_id, self.name)


class ImageCpe(Base):
    __tablename__ = 'image_cpes'

    image_user_id = Column(String(user_id_length), primary_key=True)
    image_id = Column(String(image_id_length), primary_key=True)
    pkg_type = Column(String(pkg_type_length), primary_key=True)  # java, python, gem, npm, etc

    pkg_path = Column(String(file_path_length), primary_key=True)
    cpetype = Column(String(pkg_name_length), primary_key=True)
    vendor = Column(String(pkg_name_length), primary_key=True)
    name = Column(String(pkg_name_length), primary_key=True)
    version = Column(String(pkg_version_length), primary_key=True)
    update = Column(String(pkg_version_length), primary_key=True)
    meta = Column(String(pkg_name_length), primary_key=True)

    image = relationship('Image', back_populates='cpes')

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id','images.user_id']),
        # Index('ix_image_cpe_user_img', image_user_id, image_id),
        {}
    )

    def __repr__(self):
        return '<{} user_id={}, img_id={}, name={}>'.format(self.__class__, self.image_user_id, self.image_id, self.name)

    def fixed_in(self):
        return(None)

    def get_cpestring(self):
        ret = None
        try:
            final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
            final_cpe[1] = self.cpetype
            final_cpe[2] = self.vendor
            final_cpe[3] = self.name
            final_cpe[4] = self.version
            final_cpe[5] = self.update
            final_cpe[6] = self.meta
            ret = ':'.join(final_cpe)
        except:
            ret = None

        return(ret)


class FilesystemAnalysis(Base):
    """
    A unified and compressed record of the filesystem-level entries in an image. An alternative to the FilesystemItem approach,
    this allows much faster index operations due to a smaller index, but no queries into the content of the filesystems themselves.
    """
    __tablename__ = 'image_fs_analysis_dump'

    compression_level = 6
    supported_algorithms = ['gzip']

    image_id = Column(String(image_id_length), primary_key=True)
    image_user_id = Column(String(user_id_length), primary_key=True)

    compressed_content_hash = Column(String(digest_length))
    compressed_file_json = Column(LargeBinary, nullable=False)
    total_entry_count = Column(Integer, default=0)
    file_count = Column(Integer, default=0)
    directory_count = Column(Integer, default=0)
    non_packaged_count = Column(Integer, default=0)
    suid_count = Column(Integer, default=0)
    image = relationship('Image', back_populates='fs')
    compression_algorithm = Column(String(32), default='gzip')
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    image = relationship('Image', back_populates='fs')

    _files = None

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id', 'images.user_id']),
        {}
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
        if self.compression_algorithm == 'gzip':
            return json.loads(ensure_str(zlib.decompress(ensure_bytes(self.compressed_file_json))))
        else:
            raise ValueError('Got unexpected compresssion algorithm value: {}. Expected {}'.format(self.compression_algorithm, self.supported_algorithms))

    def _files_from_json(self, file_json):
        """
        Compress and hash the file_json content
        :param file_json:
        :return:
        """
        self.compressed_file_json = zlib.compress(json.dumps(file_json).encode('utf-8'))
        self.compression_algorithm = 'gzip'
        self.compressed_content_hash = hashlib.sha256(self.compressed_file_json).hexdigest()


class AnalysisArtifact(Base):
    """
    A generic container for an analysis result that doesn't require significant structure.
    Basically wraps a key-value output from a specific analyzer.

    """

    __tablename__ = 'image_analysis_artifacts'

    image_id = Column(String(image_id_length), primary_key=True)
    image_user_id = Column(String(user_id_length), primary_key=True)
    analyzer_id = Column(String(128), primary_key=True) # The name of the analyzer (e.g. layer_info)
    analyzer_artifact = Column(String(128), primary_key=True) # The analyer artifact name (e.g. layers_to_dockerfile)
    analyzer_type = Column(String(128), primary_key=True) # The analyzer type (e.g. base, user, or extra)
    artifact_key = Column(String(256), primary_key=True)
    str_value = Column(Text)
    json_value = Column(StringJSON)
    binary_value = Column(LargeBinary)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    last_modified = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    image = relationship('Image', back_populates='analysis_artifacts')

    __table_args__ = (
        ForeignKeyConstraint(columns=[image_id, image_user_id],
                             refcolumns=['images.id', 'images.user_id']),
        {}
    )


class Image(Base):
    """
    The core image analysis record. Contains metadata about the image itself.

    """
    __tablename__ = 'images'

    id = Column(String(image_id_length), primary_key=True)
    user_id = Column(String(user_id_length), primary_key=True)  # Images are namespaced in the system to prevent overlap

    state = Column(Enum('failed', 'initializing', 'analyzing', 'analyzed', name='image_states'),
                   default='initializing')  # For now we only load analyzed images, no progress tracking
    anchore_type = Column(Enum('undefined', 'base', 'application', 'user', 'intermediate', name='anchore_image_types'),
                          default='undefined')  # TODO: verify if base or undefined should be default

    size = Column(BigInteger)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    last_modified = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    digest = Column(String(digest_length))
    distro_name = Column(String(distro_length))
    distro_version = Column(String(distro_version_length))
    like_distro = Column(String(distro_length))

    # Should be native JSON, can be handled
    layers_json = Column(StringJSON)
    docker_history_json = Column(StringJSON)
    docker_data_json = Column(StringJSON)
    familytree_json = Column(StringJSON)
    layer_info_json = Column(StringJSON)
    dockerfile_contents = Column(Text)
    dockerfile_mode = Column(String(16), default='Guessed')

    packages = relationship('ImagePackage', back_populates='image', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])
    fs = relationship('FilesystemAnalysis', uselist=False, lazy='select', cascade=['all','delete','delete-orphan'])

    # TODO - move these to ImagePackage records instead of individual tables
    gems = relationship('ImageGem', back_populates='image', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])
    npms = relationship('ImageNpm', back_populates='image', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])

    cpes = relationship('ImageCpe', back_populates='image', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])
    analysis_artifacts = relationship('AnalysisArtifact', back_populates='image', lazy='dynamic', cascade=['all','delete', 'delete-orphan'])

    @property
    def distro_namespace(self):
        if self.distro_name and self.distro_version:
            return self.distro_name + ':' + self.distro_version
        else:
            return None

    def get_packages_by_type(self, pkg_type):
        db = get_thread_scoped_session()
        typed_packages = db.query(ImagePackage).filter(ImagePackage.image_id==self.id, ImagePackage.image_user_id==self.user_id, ImagePackage.pkg_type==pkg_type).all()
        return(typed_packages)

    def vulnerabilities(self):
        """
        Load vulnerabilties for all packages in this image
        :return: list of ImagePackageVulnerabilities
        """
        db = get_thread_scoped_session()
        known_vulnerabilities = db.query(ImagePackageVulnerability).filter(
            ImagePackageVulnerability.pkg_user_id == self.user_id,
            ImagePackageVulnerability.pkg_image_id == self.id).all()
        return known_vulnerabilities

    def cpe_vulnerabilities(self):
        """
        Similar to the vulnerabilities function, but using the cpe matches instead, basically the NVD raw data source

        :return: list of (image_cpe, cpe_vulnerability) tuples
        """
        db = get_thread_scoped_session()
        cpe_vulnerabilities = db.query(ImageCpe, CpeVulnerability).filter(ImageCpe.image_id == self.id,
                                                                              ImageCpe.image_user_id == self.user_id,
                                                                              ImageCpe.name == CpeVulnerability.name,
                                                                              ImageCpe.version == CpeVulnerability.version).all()
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
        return '<Image user_id={}, id={}, distro={}, distro_version={}, created_at={}, last_modified={}>'.format(self.user_id, self.id, self.distro_name, self.distro_version, self.created_at, self.last_modified)


class ImagePackageVulnerability(Base):
    """
    Provides a mapping between ImagePackage and Vulnerabilities
    """

    __tablename__ = 'image_package_vulnerabilities'

    pkg_user_id = Column(String(user_id_length), primary_key=True)
    pkg_image_id = Column(String(image_id_length), primary_key=True)
    pkg_name = Column(String(pkg_name_length), primary_key=True)
    pkg_version = Column(String(pkg_version_length), primary_key=True)
    pkg_type = Column(String(pkg_type_length), primary_key=True)  # RHEL, DEB, APK, etc.
    pkg_arch = Column(String(16), default='N/A', primary_key=True)

    pkg_path = Column(String(file_path_length), default='pkgdb', primary_key=True)

    vulnerability_id = Column(String(vuln_id_length), primary_key=True)
    vulnerability_namespace_name = Column(String(namespace_length))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    package = relationship('ImagePackage', back_populates='vulnerabilities')
    vulnerability = relationship('Vulnerability')

    __table_args__ = (
        ForeignKeyConstraint(columns=[pkg_image_id, pkg_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path], refcolumns=[ImagePackage.image_id, ImagePackage.image_user_id, ImagePackage.name, ImagePackage.version, ImagePackage.pkg_type, ImagePackage.arch, ImagePackage.pkg_path]),
        ForeignKeyConstraint(columns=[vulnerability_id, vulnerability_namespace_name], refcolumns=[Vulnerability.id, Vulnerability.namespace_name]),
        {}
    )

    def fixed_artifact(self):
        """
        Return the FixedArtifact record given a package has been matched to the vulnerability
        :return: the matched FixedArtifact record or None if not found
        """
        if self.vulnerability.fixed_in:
            name_matches = [self.pkg_name, self.package.normalized_src_pkg]
            fixed_artifacts = [x for x in self.vulnerability.fixed_in if x.name in name_matches]
            if fixed_artifacts and len(fixed_artifacts) == 1:
                fixed_in = fixed_artifacts[0]
            elif fixed_artifacts and len(fixed_artifacts) > 1:
                # TODO version comparision logic to select the correct fixed in record.
                # Temporary workaround: return the first match after sorting by name
                fixed_in = sorted(fixed_artifacts, key=lambda fixed_artifact: fixed_artifact.name)[0]
            else:
                fixed_in = None
        else:
            fixed_in = None

        return fixed_in

    def fixed_in(self):
        """
        Return the fixed_in value given a package matched (in case there are multiple packages specified in the vuln.
        :param package: package to find a fix version for, if available
        :return: the fixed in version string if any or None if not found
        """
        fixed_in = self.fixed_artifact()
        fix_available_in = fixed_in.version if fixed_in and fixed_in.version != 'None' else None

        # NOTE: semver version format indicates a range where package
        # is vulnerable (as opposed to a value where anythng < value
        # is vulnerable, and the fix itself is known to exist), so we prepend a 'not' to indicate 'fix is available, if not in semver range'
        if fixed_in.version_format in ['semver']:
            if fix_available_in and fixed_in.fix_metadata and fixed_in.fix_metadata.get('fix_exists', False):
                fix_available_in = "! {}".format(fix_available_in)
            else:
                fix_available_in = None

        return fix_available_in

    def fix_has_no_advisory(self):
        """
        For a given package vulnerability match, if the issue won't be addressed by the vendor return True.
        Return False otherwise
        :return:
        """
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
        rec.vulnerability_id = vuln_obj.vulnerability_id if hasattr(vuln_obj, 'vulnerability_id') else vuln_obj.id
        rec.vulnerability_namespace_name = vuln_obj.namespace_name
        return rec

    def __repr__(self):
        return '<ImagePackageVulnerability img_user_id={}, img_id={}, pkg_name={}, pkg_version={}, vuln_id={}, vuln_namespace={}, pkg_path={}>'.format(self.pkg_user_id, self.pkg_image_id, self.pkg_name, self.pkg_version, self.vulnerability_id, self.vulnerability_namespace_name, self.pkg_path)

    # To support hash functions like set operations, ensure these align with primary key comparisons to ensure two identical records would match as such.
    def __eq__(self, other):
        return (isinstance(other, type(self)) and (self.pkg_user_id, self.pkg_image_id, self.pkg_name, self.pkg_version, self.pkg_type, self.pkg_arch, self.vulnerability_id, self.pkg_path) == ((other.pkg_user_id, other.pkg_image_id, other.pkg_name, other.pkg_version, other.pkg_type, other.pkg_arch, other.vulnerability_id, other.pkg_path)))

    def __hash__(self):
        return hash((self.pkg_user_id, self.pkg_image_id, self.pkg_name, self.pkg_version, self.pkg_type, self.pkg_arch, self.vulnerability_id, self.pkg_path))


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

    def _map_version(self, distro_name, distro_version, like_distro, found_mapping=None):
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
            distro = self._map_name(self.from_distro, self.from_version, self.from_like_distro, self.found_mapping)
            flavor = self._map_flavor(self.from_distro, self.from_version, self.from_like_distro, self.found_mapping)
            versions = self._map_version(self.from_distro, self.from_version, self.from_like_distro, self.found_mapping)
            return [DistroTuple(distro=distro, version=v, flavor=flavor) for v in versions]
        except:
            log.exception(
                'Failed to fully construct the mapped distro from: {}, {}, {}'.format(self.from_distro,
                                                                                      self.from_version,
                                                                                      self.from_like_distro))
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
            candidates = like_distro.split(',') if like_distro else []
            for c in candidates:
                mapping = db.query(DistroMapping).get(c)
                if mapping:
                    return mapping.flavor
            return None

    def _map_version(self, distro_name, distro_version, like_distro, found_mapping=None):
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
        patt = re.match('(\d+)\.(\d+)\.(\d+)', distro_version)
        if patt:
            major, minor, subminor = patt.groups()
            return [distro_version, '{}.{}'.format(major, minor), '{}'.format(major)]

        # Parse dow to only major
        patt = re.match('(\d+)\.(\d+)', distro_version)
        if patt:
            major, minor = patt.groups()
            return [distro_version, '{}.{}'.format(major, minor), '{}'.format(major)]

        return [distro_version]


class DistroMapping(Base):
    """
    A mapping entry between a distro with known cve feed and other similar distros.
    Used to explicitly map similar distros to a base feed for cve matches.
    """
    __tablename__ = 'distro_mappings'
    __distro_mapper_cls__ = VersionPreservingDistroMapper

    from_distro = Column(String(distro_length), primary_key=True) # The distro to be checked
    to_distro = Column(String(distro_length)) # The distro to use instead of the pk distro to do cve checks
    flavor = Column(String(distro_length)) # The distro flavor to use (e.g. RHEL, or DEB)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    @classmethod
    def distros_for(cls, distro, version, like_distro=''):
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
        name_matches = db.query(DistroMapping).filter(DistroMapping.to_distro == distro).all()
        return [DistroTuple(distro=mapping.from_distro, version=version, flavor=mapping.flavor) for mapping in name_matches]

    def __str__(self):
        return '<DistroMapping>from={} to={}, flavor={}'.format(self.from_distro, self.to_distro, self.flavor)

class DistroNamespace(object):
    """
    A helper object for holding and converting distro names and namespaces between image and vulnerability records.
    Abstracts the conversion of name, version, like_version sets into usable strings for comparing and matching records.

    The 'like' relation defines similar pkg types and cve feed sources. If distro A is like distro B, then distro A should be able to match
    against distro B's vulnerability feeds.

    """

    @classmethod
    def for_obj(cls, obj):
        if hasattr(obj, 'distro_name') and hasattr(obj, 'distro_version'):
            return DistroNamespace(getattr(obj, 'distro_name'), getattr(obj, 'distro_version'), like_distro=getattr(obj, 'like_distro', None))
        else:
            raise TypeError('Given object must have attributes: distro_name, distro_version')

    def __init__(self, name='UNKNOWN', version='UNKNOWN', like_distro=None):
        self.name = name
        self.version = version
        self.like_distro = like_distro
        self.mapping = DistroMapping.distros_for(self.name, self.version, self.like_distro)
        self.flavor = self.mapping[0].flavor if self.mapping else 'Unknown'
        self.namespace_name = DistroNamespace.as_namespace_name(self.mapping[0].distro, self.mapping[0].version)
        self.like_namespace_names = [DistroNamespace.as_namespace_name(x.distro, x.version) for x in self.mapping]


    @staticmethod
    def as_namespace_name(name, version):
        """
        Direct conversion to a single namespace name. Does not follow any 'like' relations.

        :return:
        """
        return name + ':' + version

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
        return [x.distro for x in DistroMapping.distros_mapped_to(self.name, self.version)]


class CachedPolicyEvaluation(Base):
    __tablename__ = 'policy_engine_evaluation_cache'

    user_id = Column(String, primary_key=True)
    image_id = Column(String, primary_key=True)
    eval_tag = Column(String, primary_key=True)
    bundle_id = Column(String, primary_key=True) # Need both id and digest to differentiate a new bundle vs update to bundle that requires a flush of the old record
    bundle_digest = Column(String, primary_key=True)

    result = Column(StringJSON, nullable=False) # Result struct, based on the 'type' inside, may be literal content or a reference to the archive

    created_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)
    last_modified = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    def key_tuple(self):
        return self.user_id, self.image_id, self.eval_tag, self.bundle_id, self.bundle_digest

    def _constuct_raw_result(self, result_json):
        return {
            'type': 'direct',
            'result': result_json
        }

    def _construct_remote_result(self, bucket, key, digest):
        """
        Build the result json for the db record

        :param bucket: bucket in archive to lookup result
        :param key: key in archive to lookup result
        :param digest: sha256 digest of the result
        :return:
        """
        return {
            'type': 'archive',
            'digest': digest,
            'uri': 'catalog://{bucket}/{key}'.format(bucket=bucket, key=key)
        }

    def add_raw_result(self, result_json):
        self.result = self._constuct_raw_result(result_json)

    def add_remote_result(self, bucket, key, result_digest):
        self.result = self._construct_remote_result(bucket, key, result_digest)

    def is_raw(self):
        return self.result['type'] == 'direct'

    def is_archive_ref(self):
        return self.result['type'] == 'archive'

    def archive_tuple(self):
        """
        Returns the bucket, key tuple for an archive reference
        :return:
        """

        if self.is_archive_ref():
            uri = self.result.get('uri', '')
            _, path = uri.split('catalog://', 1)
            bucket, key = path.split('/', 1)
            return bucket, key
        else:
            raise ValueError('Result type is not an archive')
