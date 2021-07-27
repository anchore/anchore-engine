"""
Interface for the vulnerabilities subsystem.

This component of the engine is hydrated by data from feeds or a local source.

The evaluation and model side of the system are specific to the data, so this is a layer on top of the
general feeds implementation as it consumes the feed data. Other components should interact with this layer.

Generally, this code has a lot of comments to help explain things since it can be somewhat subtle as to why things
work the way they do and often the behavior is a result of the range of cleanliness of the data itself.

"""
import datetime
import re
import threading
import time

from sqlalchemy import or_

from anchore_engine.common import nonos_package_types
from anchore_engine.db import (
    DistroNamespace,
    ImagePackage,
    ImagePackageVulnerability,
    Vulnerability,
    db_catalog_image,
    get_thread_scoped_session,
)
from anchore_engine.subsys import logger

# TODO: introduce a match cache for the fix key and package key to optimize the lookup and updates since its common to
# see a lot of images with the same versions of packages installed.


class ThreadLocalFeedGroupNameCache:
    """
    Simple cache used during feed syncs to caching name lookups. Here for simpler import paths, used by both feeds.VulnerabilityFeed and vulerabilities.process_updated_vulnerability functions
    """

    feed_list_cache = threading.local()

    @classmethod
    def lookup(cls, name):
        if cls.feed_list_cache and hasattr(cls.feed_list_cache, "vuln_group_list"):
            return (
                cls.feed_list_cache.vuln_group_list
                and cls.feed_list_cache.vuln_group_list.get(name, False)
            )
        else:
            return False

    @classmethod
    def add(cls, name_tuples: list):
        """
        List of (name:str, enabled:bool) tuples

        :param name_tuples:
        :return:
        """
        dict_version = {n[0]: n for n in name_tuples}
        try:
            cls.feed_list_cache.vuln_group_list.update(dict_version)
        except AttributeError:
            cls.feed_list_cache.vuln_group_list = dict_version

    @classmethod
    def flush(cls):
        try:
            cls.feed_list_cache.vuln_group_list = None
        except AttributeError:
            pass


def namespace_has_no_feed(name, version):
    """
    Returns true if the given namespace has no direct CVE feed and false if it does.

    :return: boolean if name,version tuple does not have a feed of its own
    """
    ns = DistroNamespace.as_namespace_name(name, version)
    found = ThreadLocalFeedGroupNameCache.lookup(
        ns
    )  # Returns a tuple (name, enabled:bool)
    return not found or not found[1]


def get_namespace_related_names(distro, version, distro_mapped_names: list):
    """
    Return the refined list of distro names that are served by this distro's feed.

    Implements a filter such that any namespace that has an exact matching feed group will never map to another distro's feed.
    This behavior is an artifact of an older code-based approach to distro mapping before it was data driven.

    This function can probably be removed from code path now that mappings are mutable at runtime and no longer purely
    dependent on feed groups appearing and automatically switching feeds.

    :param distro_mapped_names:
    :return:
    """
    # Filter related_names down based on the presence of actual feeds/cve data. If there is an actual feed for a name, remove it from the list.
    # Only do this if the list of related names is not just the name itself. (e.g. alpine = [alpine]).
    if distro_mapped_names != [distro]:
        # Ensure we don't include any names that actually have a feed (can happen when new feeds arrive before the mapped_names() source
        # is updated to break the 'like' relation between the distros.
        related_names = [
            x for x in distro_mapped_names if namespace_has_no_feed(x, version)
        ]

        # This is a weird case because it basically means that this distro doesn't map to itself as far as mapped_names() is
        # concerned, but since that could be code lagging data (e.g. new feed group added for a new distro), add the name itself
        # back into the list.
        if distro not in related_names and not namespace_has_no_feed(distro, version):
            related_names.append(distro)
    else:
        related_names = distro_mapped_names

    return related_names


def find_vulnerable_image_packages(vulnerability_obj):
    """
    Given a vulnerability object, find images that are affected via their package manifests.
    Result may have duplicates based on match type, caller must de-dup if desired.

    :param vulnerability_obj:
    :return: list of ImagePackage objects
    """
    db = get_thread_scoped_session()
    distro, version = vulnerability_obj.namespace_name.split(":", 1)
    dist = DistroNamespace(distro, version)
    related_names = (
        dist.mapped_names()
    )  # Returns list of names that map to this one, not including itself necessarily
    # related_names = get_namespace_related_names(distro, version, mapped_names)

    # TODO would like a better way to do the pkg_type <-> namespace_name mapping, with other side in ImagePackage.vulnerabilities_for_package
    likematch = None
    if (
        ":maven" in vulnerability_obj.namespace_name
        or "java" in vulnerability_obj.namespace_name
    ):
        likematch = "java"
    elif (
        ":ruby" in vulnerability_obj.namespace_name
        or "gem" in vulnerability_obj.namespace_name
    ):
        likematch = "gem"
    elif (
        ":js" in vulnerability_obj.namespace_name
        or "npm" in vulnerability_obj.namespace_name
    ):
        likematch = "npm"
    elif "python" in vulnerability_obj.namespace_name:
        likematch = "python"

    try:
        affected = []
        if vulnerability_obj.fixed_in:
            # Check the fixed_in records
            for fix_rec in vulnerability_obj.fixed_in:
                package_candidates = []

                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
                pkgs = (
                    db.query(ImagePackage)
                    .filter(
                        ImagePackage.distro_name.in_(related_names),
                        ImagePackage.distro_version.like(dist.version + "%"),
                        or_(
                            ImagePackage.name == fix_rec.name,
                            ImagePackage.normalized_src_pkg == fix_rec.name,
                        ),
                    )
                    .all()
                )
                package_candidates += pkgs

                # add non distro candidates
                if likematch:
                    pkgs = (
                        db.query(ImagePackage)
                        .filter(
                            ImagePackage.pkg_type.in_(nonos_package_types),
                            ImagePackage.pkg_type.like(likematch),
                            or_(
                                ImagePackage.name == fix_rec.name,
                                ImagePackage.normalized_src_pkg == fix_rec.name,
                            ),
                        )
                        .all()
                    )
                    package_candidates += pkgs

                for candidate in package_candidates:
                    if fix_rec.match_but_not_fixed(candidate):
                        affected.append(candidate)

        if vulnerability_obj.vulnerable_in:
            # Check the vulnerable_in records
            for vuln_rec in vulnerability_obj.vulnerable_in:
                package_candidates = []
                # Find packages of related distro names with compatible versions, this does not have to be precise, just an initial filter.
                pkgs = (
                    db.query(ImagePackage)
                    .filter(
                        ImagePackage.distro_name.in_(related_names),
                        ImagePackage.distro_version.like(dist.version + "%"),
                        or_(
                            ImagePackage.name == vuln_rec.name,
                            ImagePackage.normalized_src_pkg == vuln_rec.name,
                        ),
                    )
                    .all()
                )
                package_candidates += pkgs
                for candidate in package_candidates:
                    if vuln_rec.match_and_vulnerable(candidate):
                        affected.append(candidate)

        return affected
    except Exception as e:
        logger.exception(
            "Failed to query and find packages affected by vulnerability: {}".format(
                vulnerability_obj
            )
        )
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
            pkg_vulnerabilities = package.find_vulnerabilities()
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
        # log.debug("TIMER VULNERABILITIES: {}".format(time.time() - ts))

        return computed_vulnerabilties
    except Exception as e:
        logger.exception(
            "Error computing full vulnerability set for image {}/{}".format(
                image_obj.user_id, image_obj.id
            )
        )
        raise


def rescan_image(image_obj, db_session):
    """
    Rescan an image for vulnerabilities. Discards old results and rescans and persists new matches based on current data.

    :param image_obj:
    :param db_session:
    :return:
    """

    current_vulns = image_obj.vulnerabilities()
    logger.debug(
        "Removing {} current vulnerabilities for {}/{} to rescan".format(
            len(current_vulns), image_obj.user_id, image_obj.id
        )
    )
    for v in current_vulns:
        db_session.delete(v)

    db_session.flush()
    vulns = vulnerabilities_for_image(image_obj)
    logger.info(
        "Adding {} vulnerabilities from rescan to {}/{}".format(
            len(vulns), image_obj.user_id, image_obj.id
        )
    )
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

    # for rec in db_session.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_namespace_name == namespace_name):
    return (
        db_session.query(ImagePackageVulnerability)
        .filter(
            ImagePackageVulnerability.vulnerability_namespace_name == namespace_name
        )
        .delete()
    )


def merge_nvd_metadata_image_packages(
    dbsession, img_pkg_vulns, nvd_cls, cpe_cls, already_loaded_nvds=None
):
    """
    Same as merge_nvd_metadata but takes a list of ImagePackageVulnerabilities instead. Returns a list of (img pkg vuln, nvds list) tuples

    :param dbsession:
    :param img_pkg_vulns:
    :param nvd_cls:
    :param cpe_cls:
    :param already_loaded_nvds:
    :return:
    """
    merged = merge_nvd_metadata(
        dbsession,
        [x.vulnerability for x in img_pkg_vulns],
        nvd_cls,
        cpe_cls,
        already_loaded_nvds,
    )
    return zip(img_pkg_vulns, [x[1] for x in merged])


def merge_nvd_metadata(
    dbsession, vulnerability_objs, nvd_cls, cpe_cls, already_loaded_nvds=None
):
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

    result_list = [
        [
            x,
            x.get_nvd_identifiers(nvd_cls, cpe_cls)
            if isinstance(x, Vulnerability)
            else [],
        ]
        for x in vulnerability_objs
    ]
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
    count = (
        db.query(ImagePackageVulnerability)
        .filter(ImagePackageVulnerability.vulnerability_namespace_name == group_name)
        .delete()
    )
    logger.info(
        "Deleted {} vulnerability matches in flush for group {}".format(
            count, group_name
        )
    )


def process_updated_vulnerability(db, vulnerability):
    """
    Update vulnerability matches for this vulnerability. This function will add objects to the db session but
    will not commit. The caller is expected to manage the session lifecycle.

    :param: item: The updated vulnerability object
    :param: db: The db session to use, should be valid and open
    :return: list of (user_id, image_id) that were affected
    """
    logger.spew("Processing CVE update for: {}".format(vulnerability.id))
    changed_images = []

    # Find any packages already matched with the CVE ID.
    current_affected = vulnerability.current_package_vulnerabilities(db)

    # May need to remove vuln from some packages.
    if vulnerability.is_empty():
        logger.spew("Detected an empty CVE. Removing all existing matches on this CVE")

        # This is a flush, nothing can be vulnerable to this, so remove it from packages.
        if current_affected:
            logger.debug(
                "Detected {} existing matches on CVE {} to remove".format(
                    len(current_affected), vulnerability.id
                )
            )

            for pkgVuln in current_affected:
                logger.debug(
                    "Removing match on image: {}/{}".format(
                        pkgVuln.pkg_user_id, pkgVuln.pkg_image_id
                    )
                )
                db.delete(pkgVuln)
                changed_images.append((pkgVuln.pkg_user_id, pkgVuln.pkg_image_id))
    else:
        # Find impacted images for the current vulnerability
        new_vulnerable_packages = [
            ImagePackageVulnerability.from_pair(x, vulnerability)
            for x in find_vulnerable_image_packages(vulnerability)
        ]
        unique_vuln_pkgs = set(new_vulnerable_packages)
        current_match = set(current_affected)

        if len(new_vulnerable_packages) > 0:
            logger.debug(
                "Found {} packages vulnerable to cve {}".format(
                    len(new_vulnerable_packages), vulnerability.id
                )
            )
            logger.debug(
                "Dedup matches from {} to {}".format(
                    len(new_vulnerable_packages), len(unique_vuln_pkgs)
                )
            )

        # Find the diffs of any packages that were vulnerable but are no longer.
        no_longer_affected = current_match.difference(unique_vuln_pkgs)
        possibly_updated = current_match.intersection(unique_vuln_pkgs)
        new_matches = unique_vuln_pkgs.difference(current_match)

        if len(no_longer_affected) > 0:
            logger.debug(
                "Found {} packages no longer vulnerable to cve {}".format(
                    len(no_longer_affected), vulnerability.id
                )
            )
            for img_pkg_vuln in no_longer_affected:
                logger.debug(
                    "Removing old invalid match for pkg {} on cve {}".format(
                        img_pkg_vuln, vulnerability.id
                    )
                )
                db.delete(img_pkg_vuln)
            db.flush()

        for v in new_matches:
            logger.debug("Adding new vulnerability match: {}".format(v))
            db.add(v)
            changed_images.append((v.pkg_user_id, v.pkg_image_id))

        db.flush()

    logger.spew(
        "Images changed for cve {}: {}".format(vulnerability.id, changed_images)
    )

    return changed_images


def rescan_namespace(db, namespace_name: str):
    """
    Re-match all vulnerabilities in the given namespace. Does not modify any vulnerability records, only image matches for
    existing records

    :param namespace_name: e.g. 'rhel:8'
    :return:
    """
    i = 0
    logger.info(
        "Evaluating matches for all vulnerabilities in namespace {}".format(
            namespace_name
        )
    )
    total_vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.namespace_name == namespace_name)
        .count()
    )
    logger.info(
        "Found {} total vulnerability records in that namespace to re-evaluate against images in the db"
    )
    for vuln in db.query(Vulnerability).filter(
        Vulnerability.namespace_name == namespace_name
    ):
        logger.info(
            "Computing matches for {} vulnerability {}".format(namespace_name, vuln.id)
        )
        updated_images = process_updated_vulnerability(db, vuln)
        logger.info(
            "Updated {} images with a match for {}".format(
                len(updated_images) if updated_images else 0, vuln.id
            )
        )
        i += 1
        logger.info(
            "Completed {} of {} updates for {}".format(i, total_vulns, namespace_name)
        )


def get_imageId_to_record(userId, dbsession=None):
    imageId_to_record = {}

    tag_re = re.compile("([^/]+)/([^:]+):(.*)")

    imagetags = db_catalog_image.get_all_tagsummary(userId, session=dbsession)
    fulltags = {}
    tag_history = {}
    for x in imagetags:
        if x["imageId"] not in tag_history:
            tag_history[x["imageId"]] = []

        registry, repo, tag = tag_re.match(x["fulltag"]).groups()

        if x["tag_detected_at"]:
            tag_detected_at = (
                datetime.datetime.utcfromtimestamp(
                    float(int(x["tag_detected_at"]))
                ).isoformat()
                + "Z"
            )
        else:
            tag_detected_at = 0

        tag_el = {
            "registry": registry,
            "repo": repo,
            "tag": tag,
            "fulltag": x["fulltag"],
            "tag_detected_at": tag_detected_at,
        }
        tag_history[x["imageId"]].append(tag_el)

        if x["imageId"] not in imageId_to_record:
            if x["analyzed_at"]:
                analyzed_at = (
                    datetime.datetime.utcfromtimestamp(
                        float(int(x["analyzed_at"]))
                    ).isoformat()
                    + "Z"
                )
            else:
                analyzed_at = 0

            imageId_to_record[x["imageId"]] = {
                "imageDigest": x["imageDigest"],
                "imageId": x["imageId"],
                "analyzed_at": analyzed_at,
                "tag_history": tag_history[x["imageId"]],
            }

    return imageId_to_record
