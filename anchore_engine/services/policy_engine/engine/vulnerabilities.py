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

from anchore_engine.db import DistroNamespace, get_thread_scoped_session, get_session
from anchore_engine.db import Vulnerability, ImagePackage, ImagePackageVulnerability
from anchore_engine.common import nonos_package_types, os_package_types
from anchore_engine.services.policy_engine.engine.feeds.db import get_feed_json
import threading

from .logs import get_logger

log = get_logger()

# TODO: introduce a match cache for the fix key and package key to optimize the lookup and updates since its common to
# see a lot of images with the same versions of packages installed.


class ThreadLocalFeedGroupNameCache:
    """
    Simple cache used during feed syncs to caching name lookups. Here for simpler import paths, used by both feeds.VulnerabilityFeed and vulerabilities.process_updated_vulnerability functions
    """
    feed_list_cache = threading.local()

    @classmethod
    def lookup(cls, name):
        if cls.feed_list_cache and hasattr(cls.feed_list_cache, 'vuln_group_list'):
            return cls.feed_list_cache.vuln_group_list and name in cls.feed_list_cache.vuln_group_list
        else:
            return False

    @classmethod
    def add(cls, names: list):
        try:
            for n in names:
                cls.feed_list_cache.vuln_group_list.update(set(names))
        except AttributeError:
            cls.feed_list_cache.vuln_group_list = set(names)

    @classmethod
    def flush(cls):
        try:
            cls.feed_list_cache.vuln_group_list = None
        except AttributeError:
            pass


def have_vulnerabilities_for(distro_namespace_obj):
    """
    Does the system have any vulnerabilities for the given distro.

    :param distro_namespace_obj:
    :return: boolean
    """

    # All options are the same, no need to loop
    # Check all options for distro/flavor mappings
    db = get_thread_scoped_session()
    for namespace_name in distro_namespace_obj.like_namespace_names:
        feed = get_feed_json(db_session=db, feed_name='vulnerabilities')
        if feed and namespace_name in [x['name'] for x in feed.get('groups', [])]:
            # No records yet, but we have the feed, so may just not have any data yet
            return True
    else:
        return False


def namespace_has_no_feed(name, version):
    """
    Returns true if the given namespace has no direct CVE feed and false if it does.

    :return: boolean if name,version tuple does not have a feed of its own
    """
    return not ThreadLocalFeedGroupNameCache.lookup(name + ':' + version)


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


def merge_nvd_metadata_image_packages(dbsession, img_pkg_vulns, nvd_cls, cpe_cls, already_loaded_nvds=None):
    """
    Same as merge_nvd_metadata but takes a list of ImagePackageVulnerabilities instead. Returns a list of (img pkg vuln, nvds list) tuples

    :param dbsession:
    :param img_pkg_vulns:
    :param nvd_cls:
    :param cpe_cls:
    :param already_loaded_nvds:
    :return:
    """
    merged = merge_nvd_metadata(dbsession, [x.vulnerability for x in img_pkg_vulns], nvd_cls, cpe_cls, already_loaded_nvds)
    return zip(img_pkg_vulns, [x[1] for x in merged])


def merge_nvd_metadata(dbsession, vulnerability_objs, nvd_cls, cpe_cls, already_loaded_nvds=None):
    """
    Return a list of tuples of (vuln obj, list(nvd records)

    :param dbsession active db session to use for query
    :param vulnerability_objs: a list of Vulnerability objects
    :param nvd_cls the class of nvd object to use for query
    :param cpe_cls the class of nvd object to use for query
    :return: list of tuples of (Vulnerability, list(NVD objects)) tuples
    """

    if already_loaded_nvds is None:
        already_loaded_nvds = []

    result_list = [[x, x.get_nvd_identifiers(nvd_cls, cpe_cls) if isinstance(x, Vulnerability) else []] for x in vulnerability_objs]
    nvd_ids = []

    # Zip the ids into the master query list
    for id in result_list:
        nvd_ids.extend(id[1])

    # Dedup
    nvd_ids = list(set(nvd_ids).difference({rec.name for rec in already_loaded_nvds}))

    # Do the db lookup for all of them
    nvd_records = dbsession.query(nvd_cls).filter(nvd_cls.name.in_(nvd_ids)).all()
    nvd_records.extend(already_loaded_nvds)

    id_map = {x.name: x for x in nvd_records}

    # Map back to the records
    for entry in result_list:
        entry[1] = [id_map[id] for id in entry[1] if id in id_map]

    return result_list


def flush_vulnerability_matches(db, feed_name=None, group_name=None):
    """
    Delete image vuln matches for the namespacename that matches the group name
    :param db:
    :param feed_name:
    :param group_name:
    :return:
    """

    count = db.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_namespace_name == group_name).delete()
    log.info('Deleted {} rows in flush for group {}'.format(count, group_name))


def process_updated_vulnerability(db, vulnerability):
    """
    Update vulnerability matches for this vulnerability. This function will add objects to the db session but
    will not commit. The caller is expected to manage the session lifecycle.

    :param: item: The updated vulnerability object
    :param: db: The db session to use, should be valid and open
    :return: list of (user_id, image_id) that were affected
    """
    log.spew('Processing CVE update for: {}'.format(vulnerability.id))
    changed_images = []

    # Find any packages already matched with the CVE ID.
    current_affected = vulnerability.current_package_vulnerabilities(db)

    # May need to remove vuln from some packages.
    if vulnerability.is_empty():
        log.spew('Detected an empty CVE. Removing all existing matches on this CVE')

        # This is a flush, nothing can be vulnerable to this, so remove it from packages.
        if current_affected:
            log.debug('Detected {} existing matches on CVE {} to remove'.format(len(current_affected), vulnerability.id))

            for pkgVuln in current_affected:
                log.debug('Removing match on image: {}/{}'.format(pkgVuln.pkg_user_id, pkgVuln.pkg_image_id))
                db.delete(pkgVuln)
                changed_images.append((pkgVuln.pkg_user_id, pkgVuln.pkg_image_id))
    else:
        # Find impacted images for the current vulnerability
        new_vulnerable_packages = [ImagePackageVulnerability.from_pair(x, vulnerability) for x in find_vulnerable_image_packages(vulnerability)]
        unique_vuln_pkgs = set(new_vulnerable_packages)
        current_match = set(current_affected)

        if len(new_vulnerable_packages) > 0:
            log.debug('Found {} packages vulnerable to cve {}'.format(len(new_vulnerable_packages), vulnerability.id))
            log.debug('Dedup matches from {} to {}'.format(len(new_vulnerable_packages), len(unique_vuln_pkgs)))

        # Find the diffs of any packages that were vulnerable but are no longer.
        no_longer_affected = current_match.difference(unique_vuln_pkgs)
        possibly_updated = current_match.intersection(unique_vuln_pkgs)
        new_matches = unique_vuln_pkgs.difference(current_match)

        if len(no_longer_affected) > 0:
            log.debug('Found {} packages no longer vulnerable to cve {}'.format(len(no_longer_affected), vulnerability.id))
            for img_pkg_vuln in no_longer_affected:
                log.debug('Removing old invalid match for pkg {} on cve {}'.format(img_pkg_vuln, vulnerability.id))
                db.delete(img_pkg_vuln)
            db.flush()

        for v in new_matches:
            log.debug('Adding new vulnerability match: {}'.format(v))
            db.add(v)
            changed_images.append((v.pkg_user_id, v.pkg_image_id))

        db.flush()

    log.spew('Images changed for cve {}: {}'.format(vulnerability.id, changed_images))

    return changed_images