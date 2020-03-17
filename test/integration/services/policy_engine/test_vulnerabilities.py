import datetime
import json
from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.db import get_thread_scoped_session, end_session, Image, DistroNamespace
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask, FeedsUpdateTask, rescan_image
from anchore_engine.services.policy_engine.engine.feeds.sync import DataFeeds
from test.integration.services.policy_engine.utils import reset_feed_sync_time
from anchore_engine.services.policy_engine import _init_distro_mappings


logger.enable_test_logging()


def _load_images(test_env):
    logger.info('Loading images')
    image_results = []
    try:
        for img_id, path in test_env.image_exports():
            logger.info('Loading {}'.format(img_id))
            file_url = 'file://' + path
            i = ImageLoadTask(user_id='0', image_id=img_id, url=file_url).execute()
            if not i:
                logger.info('Could not load image {}, already in system, ot an exception'.format(img_id))
        logger.info('Load complete')
    finally:
        end_session()


def check_all_imgs_vuln():
    db = get_thread_scoped_session()
    try:
        for img in db.query(Image).all():
            logger.info('Checking vulnerabilities for image: {}'.format(img.id))
            if not img:
                logger.info('No image found with id: {}'.format(img.id))
                raise Exception('Should have image')
            vulns = vulnerabilities.vulnerabilities_for_image(img)

            for v in vulns:
                db.merge(v)
            db.commit()

            logger.info('Found: {}'.format(vulns))
    except Exception as e:
        logger.info('Error! {}'.format(e))
        end_session()


def sync_feeds(test_env, up_to=None):
    if up_to:
        test_env.set_max_feed_time(up_to)

    logger.info('Syncing vuln and packages')
    DataFeeds.__scratch_dir__ = '/tmp'
    DataFeeds.sync(['vulnerabilities', 'packages'], feed_client=test_env.feed_client)
    logger.info('Sync complete')

def test_namespace_support(test_data_env):
    _init_distro_mappings()
    sync_feeds(test_data_env)

    # Not exhaustive, only for the feeds directly in the test data set
    expected = [
        DistroNamespace(name='alpine', version='3.6', like_distro='alpine'),
        DistroNamespace(name='centos', version='7', like_distro='centos'),
        DistroNamespace(name='centos', version='7.1', like_distro='centos'),
        DistroNamespace(name='centos', version='7.3', like_distro='centos'),

        DistroNamespace(name='ol', version='7.3', like_distro='centos'),
        DistroNamespace(name='rhel', version='7.1', like_distro='centos'),

        DistroNamespace(name='debian', version='9', like_distro='debian'),

        DistroNamespace(name='ubuntu', version='16.10', like_distro='ubuntu')
    ]

    fail = [
        DistroNamespace(name='alpine', version='3.1', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.1.1', like_distro='alpine'),

        DistroNamespace(name='busybox', version='3', like_distro='busybox'),
        DistroNamespace(name='linuxmint', version='16', like_distro='debian'),
        DistroNamespace(name='redhat', version='6', like_distro='centos'),

        DistroNamespace(name='ubuntu', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='centos', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='debian', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='rhel', version='1.0', like_distro='ubuntu'),
        DistroNamespace(name='busybox', version='1.0', like_distro='busybox'),
        DistroNamespace(name='alpine', version='11.0', like_distro='ubuntu'),
        DistroNamespace(name='fedora', version='25', like_distro='fedora'),
        DistroNamespace(name='mageia', version='5', like_distro='mandriva,fedora')
    ]

    for i in expected:
        assert vulnerabilities.have_vulnerabilities_for(i), 'Expected vulns for namespace {}'.format(i.namespace_name)

    for i in fail:
        assert not vulnerabilities.have_vulnerabilities_for(i), 'Did not expect vulns for namespace {}'.format(i.namespace_name)


def check_fix_version(test_env):
    logger.info('Checking fix versions')
    db = get_thread_scoped_session()
    img = db.query(Image).get((test_env.get_images_named('ruby')[0][0], '0'))

    vulns = img.vulnerabilities()
    for vuln in vulns:
        if vuln.vulnerability.fixed_in:
            fixes_in = [x for x in vuln.vulnerability.fixed_in if x.name == vuln.pkg_name or x.name == vuln.package.normalized_src_pkg]
            fix_available_in = fixes_in[0].version if fixes_in else 'None'
        else:
            fix_available_in = 'None'
        logger.info('{} Fix version: {}'.format(vuln.vulnerability_id, fix_available_in))


def _rescan_cve(img_id):
    db = get_thread_scoped_session()
    try:
        img = db.query(Image).filter_by(user_id='0', id=img_id).one_or_none()
        v = rescan_image(db, img)
        db.commit()
        return v
    except:
        db.rollback()
        raise


def _img_vulns(id):
    db = get_thread_scoped_session()
    try:
        img = db.query(Image).filter_by(id=id, user_id='0').one_or_none()
        assert img, 'Image not found {}'.format(id)
        total_vulns = [str(x) for x in img.vulnerabilities()] + [str(y) for y in img.cpe_vulnerabilities(None, None)]
        return total_vulns
    finally:
        db.rollback()


def test_vuln_image_updates(test_data_env):
    sync_feeds(test_data_env, up_to=datetime.datetime(2017, 6, 1))
    _load_images(test_data_env)

    # Get the first set
    initial_vulns = _img_vulns(test_data_env.get_images_named('ruby')[0][0])

    # Rollback the sync time to get another sync with data
    db = get_thread_scoped_session()
    try:
        f = reset_feed_sync_time(db, datetime.datetime(2017, 6, 1), feed_name='vulnerabilities')
        db.add(f)
        db.commit()
    except:
        logger.exception('Exception commiting update of feed sync timestamps')
        db.rollback()

    # Sync again to get new merged data
    sync_feeds(test_data_env, up_to=datetime.datetime.utcnow())
    check_fix_version(test_data_env)

    rescan_img_id = list(test_data_env.image_map.keys())[0]
    updated_vulns = _img_vulns(test_data_env.get_images_named('ruby')[0][0])
    logger.info(json.dumps(updated_vulns, indent=2))

    #_rescan_cve('7b3dce19c46b752708da38a602decbb1cc4906c8c1f1a19b620158926c199930')


def test_have_vulnerabilities_for(test_data_env):
    _init_distro_mappings()
    sync_feeds(test_data_env)

    failz = DistroNamespace(name='somecrzy', version='8', like_distro='debian')
    passes = DistroNamespace(name='debian', version='8', like_distro='debian')
    assert not vulnerabilities.have_vulnerabilities_for(failz), 'Should not have vulns for ' + failz.namespace_name
    assert vulnerabilities.have_vulnerabilities_for(passes), 'Should have vulns for ' + passes.namespace_name
