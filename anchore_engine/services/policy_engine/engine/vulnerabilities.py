"""
Interface for the vulnerabilities subsystem.

This component of the engine is hydrated by data from feeds or a local source.

The evaluation and model side of the system are specific to the data, so this is a layer on top of the
general feeds implementation as it consumes the feed data. Other components should interact with this layer.

Generally, this code has a lot of comments to help explain things since it can be somewhat subtle as to why things
work the way they do and often the behavior is a result of the range of cleanliness of the data itself.

"""

from sqlalchemy import or_

from anchore_engine.db import DistroNamespace, get_thread_scoped_session
from anchore_engine.db import Vulnerability, FixedArtifact, VulnerableArtifact, ImagePackage, \
    ImagePackageVulnerability
from .feeds import DataFeeds, VulnerabilityFeed
from .logs import get_logger
from .util.apk import compare_versions as apkg_compare_versions
from .util.deb import compare_versions as dpkg_compare_versions
from .util.rpm import compare_versions as rpm_compare_versions

log = get_logger()

# TODO: introduce a match cache for the fix key and package key to optimize the lookup and updates since its common to
# see a lot of images with the same versions of packages installed.


# TODO: zhill - move this into a method on the FixedArtifact object
def match_but_not_fixed(fix_obj, package_obj):
    """
    Does the FixedArtifact match the package as a vulnerability such that the fix indicates the package is *not* fixed and is
    therefore vulnerable.

    :param fix_obj: as FixedArtifact record
    :param package_obj: an ImagePackage record
    :return: True if the names match and the fix record indicates the package is vulnerable and not fixed. False if no match or fix is applied and no vulnerability match
    """
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

    # Newer or the same
    return False


# TODO: zhill - move this into a method on the VulnerableArtifact object
def match_and_vulnerable(vuln_obj, package_obj):
    """
    Given a VulnerableArtifact record, is the given package object a match indicating that the package is vulnerable.

    :param vuln_obj:
    :param package_obj:
    :param has_fix: boolean indicating if there is a corresponding fix record
    :return:
    """
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


def have_vulnerabilities_for(distro_namespace_obj):
    """
    Does the system have any vulnerabilities for the given distro.

    :param distro_namespace_obj:
    :return: boolean
    """
    db = get_thread_scoped_session()

    # All options are the same, no need to loop
    # Check all options for distro/flavor mappings
    vulnerability_feed = DataFeeds.instance().vulnerabilities

    for namespace_name in distro_namespace_obj.like_namespace_names:
        # Check feed names
        if vulnerability_feed.group_by_name(namespace_name):
            # No records yet, but we have the feed, so may just not have any data yet
            return True
    else:
        return False


# TODO: zhill - an move this to a method on the package object
def vulnerabilities_for_package(package_obj):
    """
    Given an ImagePackage object, return the vulnerabilities that it matches.

    :param package_obj:
    :return: list of Vulnerability objects
    """
    log.debug('Finding vulnerabilities for package: {} - {}'.format(package_obj.name, package_obj.version))
    matches = []
    dist = DistroNamespace(package_obj.distro_name, package_obj.distro_version, package_obj.like_distro)

    db = get_thread_scoped_session()
    namespace_name_to_use = dist.namespace_name

    # All options are the same, no need to loop
    if len(set(dist.like_namespace_names)) > 1:
        # Look for exact match first
        if not DataFeeds.instance().vulnerabilities.group_by_name(dist.namespace_name):
            # Check all options for distro/flavor mappings, stop at first with records present
            for namespace_name in dist.like_namespace_names:
                record_count = db.query(Vulnerability).filter(Vulnerability.namespace_name == namespace_name).count()
                if record_count > 0:
                    namespace_name_to_use = namespace_name
                    break

    fix_candidates, vulnerable_candidates = candidates_for_package(package_obj, namespace_name_to_use)

    for candidate in fix_candidates:
        # De-dup evaluations based on the underlying vulnerability_id. For packages where src has many binary builds, once we have a match we have a match.
        if candidate.vulnerability_id not in [x.vulnerability_id for x in matches] and match_but_not_fixed(candidate, package_obj):
            matches.append(candidate)

    for candidate in vulnerable_candidates:
        if candidate.vulnerability_id not in [x.vulnerability_id for x in matches] and match_and_vulnerable(candidate, package_obj):
            matches.append(candidate)

    return matches


def candidates_for_package(package_obj, distro_namespace=None):
    """
    Return all vulnerabilities for the named package with the specified distro. Will apply to any version
    of the package. If version is used, will filter to only those for the specified version.

    :param package_obj: the package to match against
    :param distro_namespace: the DistroNamespace object to match against (typically computed
    :return: List of Vulnerabilities
    """

    db = get_thread_scoped_session()

    if not distro_namespace:
        namespace_name = DistroNamespace.for_obj(package_obj).namespace_name
    else:
        namespace_name = distro_namespace


    # Match the namespace and package name or src pkg name
    fix_candidates = db.query(FixedArtifact).filter(FixedArtifact.namespace_name == namespace_name,
                                                        or_(FixedArtifact.name == package_obj.name, FixedArtifact.name == package_obj.normalized_src_pkg)).all()

    # Match the namespace and package name or src pkg name
    vulnerable_candidates = db.query(VulnerableArtifact).filter(VulnerableArtifact.namespace_name == namespace_name,
                                                                or_(VulnerableArtifact.name == package_obj.name, VulnerableArtifact.name == package_obj.normalized_src_pkg)).all()

    return fix_candidates, vulnerable_candidates


def get_vulnerable_packages(vulnerability_list):
    """
    Run the pipeline for updating image vulnerabilities on the specified list of new/updated/removed records.

    :param vulnerability_list: a list of vulnerability update events
    :return: list of image ids that were modified
    """

    vulnerability_events_by_namespace = {}
    affected = []

    for event in vulnerability_list:
        if event['namespace'] not in vulnerability_events_by_namespace:
            vulnerability_events_by_namespace[event['namespace']] = []

        vulnerability_events_by_namespace[event['namespace']].append(event)

    db = get_thread_scoped_session()
    for namespace, vulns in list(vulnerability_events_by_namespace.items()):
        for vuln in vulns:
            packages = find_vulnerable_image_packages(vuln)
            for pkg in packages:
                img_pkg_v = ImagePackageVulnerability.from_pair(pkg, vuln)
                img_pkg_v = db.merge(img_pkg_v)
                affected.append(img_pkg_v)

    return affected


def namespace_has_no_feed(name, version):
    """
    Returns true if the given namespace has no direct CVE feed and false if it does.

    :param candidate_namespace: the namespace of the cve item being checked
    :param related_name: the namespace to check and validate if it should remain on the list or if it has its own feed
    :return: boolean if related_name does not have a feed of its own and should use the candidate_namespace feed
    """
    return not VulnerabilityFeed.cached_group_name_lookup(name + ':' + version)


def find_vulnerable_image_packages(vulnerability_obj):
    """
    Given a vulnerability object, find images that are affected via their package manifests.
    Result may have duplicates based on match type, caller must de-dup if desired.

    :param vulnerability_obj:
    :return: list of ImagePackage objects
    """
    db = get_thread_scoped_session()
    distro, version = vulnerability_obj.namespace_name.split(':', 1)
    dist = DistroNamespace(distro, version)
    related_names = dist.mapped_names() # Returns list of names that map to this one, not including itself necessarily

    # Filter related_names down based on the presence of actual feeds/cve data. If there is an actual feed for a name, remove it from the list.
    # Only do this if the list of related names is not just the name itself. (e.g. alpine = [alpine]).
    if related_names != [distro]:
        # Ensure we don't include any names that actually have a feed (can happen when new feeds arrive before the mapped_names() source
        # is updated to break the 'like' relation between the distros.
        related_names = [x for x in related_names if namespace_has_no_feed(x, version)]

        # This is a weird case because it basically means that this distro doesn't map to itself as far as mapped_names() is
        # concerned, but since that could be code lagging data (e.g. new feed group added for a new distro), add the name itself
        # back into the list.
        if distro not in related_names and not namespace_has_no_feed(distro, version):
            related_names.append(distro)

    try:
        affected = []
        if vulnerability_obj.fixed_in:
            # Check the fixed_in records
            for fix_rec in vulnerability_obj.fixed_in:
                package_candidates = []

                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
                pkgs = db.query(ImagePackage).filter(ImagePackage.distro_name.in_(related_names), ImagePackage.distro_version.like(dist.version + '%'), or_(ImagePackage.name == fix_rec.name, ImagePackage.normalized_src_pkg == fix_rec.name)).all()
                package_candidates += pkgs

                for candidate in package_candidates:
                    if match_but_not_fixed(fix_rec, candidate):
                        affected.append(candidate)

        if vulnerability_obj.vulnerable_in:
            # Check the vulnerable_in records
            for vuln_rec in vulnerability_obj.vulnerable_in:
                package_candidates = []

                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
                pkgs = db.query(ImagePackage).filter(ImagePackage.distro_name.in_(related_names),
                                                     ImagePackage.distro_version.like(dist.version + '%'),
                                                     or_(ImagePackage.name == fix_rec.name,
                                                         ImagePackage.normalized_src_pkg == fix_rec.name)).all()
                package_candidates += pkgs
                for candidate in package_candidates:
                    if match_and_vulnerable(vuln_rec, candidate):
                        affected.append(candidate)

        return affected
    except Exception as e:
        log.exception('Failed to query and find packages affected by vulnerability: {}'.format(vulnerability_obj))
        raise


def vulnerabilities_for_image(image_obj):
    """
    Return the list of vulnerabilities for the specified image id by recalculating the matches for the image. Ignores
    any persisted matches. Query only, does not update the data. Caller must add returned results to a db session and commit
    in order to persist.

    :param image_obj: the image
    :return: list of ImagePackageVulnerability records for the packages in the given image
    """

    # Recompute. Session and persistence in the session is up to the caller
    try:
        computed_vulnerabilties = []
        for package in image_obj.packages:
            pkg_vulnerabilities = vulnerabilities_for_package(package)
            for v in pkg_vulnerabilities:
                img_v = ImagePackageVulnerability()
                img_v.pkg_image_id = image_obj.id
                img_v.pkg_user_id = image_obj.user_id
                img_v.pkg_name = package.name
                img_v.pkg_type = package.pkg_type
                img_v.pkg_arch = package.arch
                img_v.pkg_version = package.version
                img_v.vulnerability_id = v.vulnerability_id
                img_v.vulnerability_namespace_name = v.namespace_name
                computed_vulnerabilties.append(img_v)
        return computed_vulnerabilties
    except Exception as e:
        log.exception('Error computing full vulnerability set for image {}/{}'.format(image_obj.user_id, image_obj.id))
        raise


def rescan_image(image_obj, db_session):
    """
    Rescan an image for vulnerabilities. Discards old results and rescans and persists new matches based on current data.

    :param image_obj:
    :param db_session:
    :return:
    """

    current_vulns = image_obj.vulnerabilities()
    log.debug('Removing {} current vulnerabilities for {}/{} to rescan'.format(len(current_vulns), image_obj.user_id, image_obj.id))
    for v in current_vulns:
        db_session.delete(v)

    db_session.flush()
    vulns = vulnerabilities_for_image(image_obj)
    log.info('Adding {} vulnerabilities from rescan to {}/{}'.format(len(vulns), image_obj.user_id, image_obj.id))
    for v in vulns:
        db_session.add(v)
    db_session.flush()

    return vulns


def delete_matches(namespace_name, db_session):
    """
    Flush all vuln matches for the specified namespace.

    :param namespace_name:
    :return: count of records deleted
    """

    #for rec in db_session.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_namespace_name == namespace_name):
    return db_session.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_namespace_name == namespace_name).delete()

