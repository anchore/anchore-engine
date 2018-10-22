"""
Interface for the vulnerabilities subsystem.

This component of the engine is hydrated by data from feeds or a local source.

The evaluation and model side of the system are specific to the data, so this is a layer on top of the
general feeds implementation as it consumes the feed data. Other components should interact with this layer.

Generally, this code has a lot of comments to help explain things since it can be somewhat subtle as to why things
work the way they do and often the behavior is a result of the range of cleanliness of the data itself.

"""
import time

from sqlalchemy import or_

from anchore_engine.db import DistroNamespace, get_thread_scoped_session
from anchore_engine.db import Vulnerability, FixedArtifact, ImagePackage, ImagePackageVulnerability
from anchore_engine.common import nonos_package_types, os_package_types

from .feeds import DataFeeds, VulnerabilityFeed
from .logs import get_logger

log = get_logger()

# TODO: introduce a match cache for the fix key and package key to optimize the lookup and updates since its common to
# see a lot of images with the same versions of packages installed.


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

    # TODO would like a better way to do the pkg_type <-> namespace_name mapping, with other side in ImagePackage.vulnerabilities_for_package
    likematch = None
    if ':maven' in vulnerability_obj.namespace_name or 'java' in vulnerability_obj.namespace_name:
        likematch = 'java'
    elif ':ruby' in vulnerability_obj.namespace_name or 'gem' in vulnerability_obj.namespace_name:
        likematch = 'gem'
    elif ':js' in vulnerability_obj.namespace_name or 'npm' in vulnerability_obj.namespace_name:
        likematch = 'npm'
    elif 'python' in vulnerability_obj.namespace_name:
        likematch = 'python'

    try:
        affected = []
        if vulnerability_obj.fixed_in:
            # Check the fixed_in records
            for fix_rec in vulnerability_obj.fixed_in:
                package_candidates = []

                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
                pkgs = db.query(ImagePackage).filter(ImagePackage.distro_name.in_(related_names), ImagePackage.distro_version.like(dist.version + '%'), or_(ImagePackage.name == fix_rec.name, ImagePackage.normalized_src_pkg == fix_rec.name)).all()
                package_candidates += pkgs

                # add non distro candidates
                if likematch:
                    pkgs = db.query(ImagePackage).filter(ImagePackage.pkg_type.in_(nonos_package_types), ImagePackage.pkg_type.like(likematch), or_(ImagePackage.name == fix_rec.name, ImagePackage.normalized_src_pkg == fix_rec.name)).all()
                    package_candidates += pkgs

                for candidate in package_candidates:
                    if fix_rec.match_but_not_fixed(candidate):
                        affected.append(candidate)

#        if vulnerability_obj.vulnerable_in:
#            # Check the vulnerable_in records
#            for vuln_rec in vulnerability_obj.vulnerable_in:
#                package_candidates = []
#                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
#                pkgs = db.query(ImagePackage).filter(ImagePackage.distro_name.in_(related_names),
#                                                    ImagePackage.distro_version.like(dist.version + '%'),
#                                                    or_(ImagePackage.name == fix_rec.name,
#                                                        ImagePackage.normalized_src_pkg == fix_rec.name)).all()
#               package_candidates += pkgs
#               for candidate in package_candidates:
#                   if vuln_rec.match_and_vulnerable(candidate):
#                       affected.append(candidate)

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
        ts = time.time()
        computed_vulnerabilties = []
        for package in image_obj.packages:
            pkg_vulnerabilities = package.vulnerabilities_for_package()
            for v in pkg_vulnerabilities:
                img_v = ImagePackageVulnerability()
                img_v.pkg_image_id = image_obj.id
                img_v.pkg_user_id = image_obj.user_id
                img_v.pkg_name = package.name
                img_v.pkg_type = package.pkg_type
                img_v.pkg_arch = package.arch
                img_v.pkg_version = package.version
                img_v.pkg_path = package.pkg_path
                img_v.vulnerability_id = v.vulnerability_id
                img_v.vulnerability_namespace_name = v.namespace_name
                computed_vulnerabilties.append(img_v)
        #log.debug("TIMER VULNERABILITIES: {}".format(time.time() - ts))

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

