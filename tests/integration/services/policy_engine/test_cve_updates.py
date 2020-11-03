"""
This is an integration-level test for checking CVE updates at fine granularity.
"""
import sqlalchemy.exc

from anchore_engine.db import (
    get_thread_scoped_session as get_session,
    Image,
    ImagePackage,
    Vulnerability,
    VulnerableArtifact,
    FixedArtifact,
)
from anchore_engine.services.policy_engine.engine.feeds import feeds
from anchore_engine.subsys import logger


logger.enable_test_logging(level="DEBUG")


def test_cve_updates(test_data_env):
    test_env = test_data_env
    test_env.init_feeds()

    test_user_id = "test1"
    test_img_id = "img1"
    test_image = Image(
        user_id=test_user_id, id=test_img_id, distro_name="centos", distro_version="7"
    )
    test_image.familytree_json = [test_img_id]
    test_image.layers_json = [test_img_id]
    test_image.layer_info_json = ["somelayer_here"]
    test_image.like_distro = "centos"
    test_image.state = "analyzed"
    test_image.digest = "digest1"
    test_image.anchore_type = "undefined"
    test_image.dockerfile_mode = "Guessed"
    test_image.docker_history_json = ["line1", "line2"]
    test_image.docker_data_json = {"Config": {}, "ContainerConfig": {}}
    test_image.dockerfile_contents = "FROM BLAH"

    test_package = ImagePackage(
        image_user_id=test_user_id,
        image_id=test_img_id,
        name="testpackage",
        version="1.0",
        pkg_type="RPM",
    )
    test_package.src_pkg = "testpackage"
    test_package.distro_name = "centos"
    test_package.distro_version = "7"
    test_package.like_distro = "centos"
    test_package.license = "apache2"
    test_package.fullversion = "1.0"
    test_package.normalized_src_pkg = "1.0"
    test_package.release = ""
    test_package.size = 1000
    test_package.origin = "upstream"
    test_package.arch = "x86_64"
    test_package.image = test_image

    test_cve = Vulnerability(id="CVE123", namespace_name="centos:7")
    test_cve.severity = "High"
    test_cve.description = "some test cve"
    test_cve.cvss2_score = "1.0"
    test_cve.metadata_json = {}
    test_cve.cvss2_vectors = ""
    test_cve.link = "http://mitre.com/cve123"

    test_fixedin = FixedArtifact(vulnerability_id=test_cve.id)
    test_fixedin.name = "testpackage"
    test_fixedin.version = "1.1"
    test_fixedin.version_format = "rpm"
    test_fixedin.epochless_version = "1.1"
    test_fixedin.include_later_versions = True
    test_fixedin.parent = test_cve
    test_cve.fixed_in = [test_fixedin]

    test_vulnin = VulnerableArtifact(vulnerability_id=test_cve.id)
    test_vulnin.name = "testpackage"
    test_vulnin.version = "0.9"
    test_vulnin.epochless_version = "0.9"
    test_vulnin.namespace_name = "centos:7"
    test_vulnin.version_format = "rpm"
    test_vulnin.include_previous_versions = False
    test_vulnin.parent = test_cve
    test_cve.vulnerable_in = [test_vulnin]

    db = get_session()
    try:
        db.add(test_image)
        db.add(test_package)
        db.commit()
    except sqlalchemy.exc.IntegrityError:
        db.rollback()
    except Exception:
        logger.exception("Unexpected failure")
        raise

    db = get_session()
    try:
        db.add(test_cve)
        feeds.process_updated_vulnerability(db, test_cve)
        db.commit()
    except sqlalchemy.exc.IntegrityError:
        logger.exception("Failed!")
        db.rollback()
    finally:
        db = get_session()
        i = db.query(Image).get((test_img_id, test_user_id))
        print(("Vulns: {}".format(i.vulnerabilities())))
        db.commit()

    test_cve2 = Vulnerability(id="CVE123", namespace_name="centos:7")
    test_cve2.severity = "Medium"
    test_cve2.description = "some test cve"
    test_cve2.cvss2_score = "1.0"
    test_cve2.metadata_json = {}
    test_cve2.cvss2_vectors = ""
    test_cve2.link = "http://mitre.com/cve123"
    fix2 = FixedArtifact(name="pkg2", version="1.2", epochless_version="1.2")
    fix2.namespace_name = "centos:7"
    fix2.vulnerability_id = test_cve2.id
    test_cve2.fixed_in = [fix2]

    db = get_session()
    try:
        t2 = db.merge(test_cve2)
        db.add(t2)
        feeds.process_updated_vulnerability(db, t2)
        db.commit()
    except sqlalchemy.exc.IntegrityError:
        logger.exception("Failed!")
        db.rollback()
    finally:
        db = get_session()
        i = db.query(Image).get((test_img_id, test_user_id))
        print(("Vulns: {}".format(i.vulnerabilities())))
        db.commit()


def test_github_advisory_fixed_in(test_data_env):
    test_env = test_data_env
    test_env.init_feeds()

    test_user_id = "test1"
    test_img_id = "img1"
    test_image = Image(
        user_id=test_user_id, id=test_img_id, distro_name="centos", distro_version="7"
    )
    test_image.familytree_json = [test_img_id]
    test_image.layers_json = [test_img_id]
    test_image.layer_info_json = ["somelayer_here"]
    test_image.like_distro = "centos"
    test_image.state = "analyzed"
    test_image.digest = "digest1"
    test_image.anchore_type = "undefined"
    test_image.dockerfile_mode = "Guessed"
    test_image.docker_history_json = ["line1", "line2"]
    test_image.docker_data_json = {"Config": {}, "ContainerConfig": {}}
    test_image.dockerfile_contents = "FROM BLAH"

    test_package = ImagePackage(
        image_user_id=test_user_id,
        image_id=test_img_id,
        name="testpackage",
        version="1.0",
        pkg_type="python",
    )
    test_package.src_pkg = "testpackage"
    test_package.distro_name = "centos"
    test_package.distro_version = "7"
    test_package.like_distro = "centos"
    test_package.license = "apache2"
    test_package.fullversion = "1.0"
    test_package.normalized_src_pkg = "1.0"
    test_package.release = ""
    test_package.size = 1000
    test_package.origin = "upstream"
    test_package.arch = "x86_64"
    test_package.image = test_image

    test_cve = Vulnerability(id="GHSA-rpch-cqj9-h65r", namespace_name="github:python")
    test_cve.severity = "High"
    test_cve.description = "some advisory ghsa"
    test_cve.link = "http://mitre.com/cve123"

    test_fixedin = FixedArtifact(vulnerability_id=test_cve.id)
    test_fixedin.name = "testpackage"
    test_fixedin.version = "None"
    test_fixedin.fix_metadata = {"first_patched_version": "1.2"}
    test_fixedin.version_format = "semver"
    test_fixedin.parent = test_cve
    test_cve.fixed_in = [test_fixedin]

    db = get_session()
    try:
        db.add(test_image)
        db.add(test_package)
        db.commit()
    except sqlalchemy.exc.IntegrityError:
        db.rollback()
    except Exception:
        logger.exception("Unexpected failure")
        raise

    db = get_session()
    # XXX This needs to be a fixture
    try:
        db.add(test_cve)
        feeds.process_updated_vulnerability(db, test_cve)
        db.commit()
    except sqlalchemy.exc.IntegrityError:
        logger.exception("Failed!")
        db.rollback()

    db = get_session()
    image_vuln = db.query(Image).get((test_img_id, test_user_id))
    # should be one vulnerability
    vulnerabilities = image_vuln.vulnerabilities()
    assert len(vulnerabilities) == 1
    img_pkg_vuln = vulnerabilities[0]
    assert img_pkg_vuln.fixed_in() == "1.2"
