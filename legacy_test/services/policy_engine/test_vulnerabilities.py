import logging
import datetime
import os
from anchore_engine.services.policy_engine.engine import vulnerabilities
from anchore_engine.db import get_thread_scoped_session, end_session, Image, DistroNamespace
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask, FeedsUpdateTask
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.api.controllers.synchronous_operations import get_image_vulnerabilities
from legacy_test.services.policy_engine.utils import init_db, LocalTestDataEnvironment
from legacy_test.services.policy_engine.feeds import reset_feed_sync_time

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

test_env = LocalTestDataEnvironment(os.environ['ANCHORE_ENGINE_TESTING_HOME'])
test_env.init_feeds()

test_image_ids = {
    'busybox': 'c75bebcdd211f41b3a460c7bf82970ed6c75acaab9cd4c9a4e125b03ca113798',
    'node': '6c792d9195914c8038f4cabd9356a5af47ead140b87682c8651edd55b010686c',
    'centos': '8140d0c64310d4e290bf3938757837dbb8f806acba0cb3f6a852558074345348',
    'ruby': 'f5cfccf111795cc67c1736df6ad1832afbd4842533b5a897d91e8d6122963657',
    'alpine': '02674b9cb179d57c68b526733adf38b458bd31ba0abff0c2bf5ceca5bad72cd9',
    'debian8': '4594f2fd77bf7ae4ad2b284a60e4eebb1a73b0859fe611b94f4245a6872d803e',
    'debian9': '3e83c23dba6a16cd936a3dc044df71b26706c5a4c28181bc3ca4a4af9f5f38ee',
    'fedora': '15895ef0b3b2b4e61bf03d38f82b42011ff7f226c681705a4022ae3d1d643888',
    'nginx': 'c246cd3dd41d35f9deda43609cdeaa9aaf04d3658f9c5e38aad25c4ea5efee10'
}


def init_db_persisted(create_new=False):
    global test_env
    init_db(test_env.mk_db(generate=create_new))

def load_images():
    log.info('Loading images')
    image_results = []
    try:
        for img_id, path in test_env.image_exports():
            log.info('Loading {}'.format(img_id))
            file_url = 'file:///' + path
            i = ImageLoadTask(user_id='0', image_id=img_id, url=file_url).execute()
            if not i:
                log.info('Could not load image {}, already in system, ot an exception'.format(img_id))
        log.info('Load complete')
    finally:
        end_session()


def check_vuln():
    db = get_thread_scoped_session()
    try:
        for img in db.query(Image).all():
            log.info('Checking vulnerabilities for image: {}'.format(img.id))
            if not img:
                log.info('No image found with id: {}'.format(img.id))
                raise Exception('Should have image')
            vulns = vulnerabilities.vulnerabilities_for_image(img)

            for v in vulns:
                db.merge(v)
            db.commit()

            log.info('Found: {}'.format(vulns))
    except Exception as e:
        log.info('Error! {}'.format(e))
        end_session()


def sync_feeds(up_to=None):
    df = DataFeeds.instance()
    if up_to:
        global test_env
        test_env.set_max_feed_time(up_to)

    log.info('Syncing vuln')
    df.vulnerabilities.sync(item_processing_fn=FeedsUpdateTask.process_updated_vulnerability)
    log.info('Syncing packages')
    df.packages.sync()
    log.info('Sync complete')

def namespace_support_test():
    init_db_persisted()
    expected = [
        DistroNamespace(name='alpine', version='3.3', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.4', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.5', like_distro='alpine'),
        DistroNamespace(name='alpine', version='3.6', like_distro='alpine'),

        DistroNamespace(name='centos', version='5', like_distro='centos'),
        DistroNamespace(name='centos', version='6', like_distro='centos'),
        DistroNamespace(name='centos', version='7', like_distro='centos'),
        DistroNamespace(name='centos', version='7.1', like_distro='centos'),
        DistroNamespace(name='centos', version='7.3', like_distro='centos'),

        DistroNamespace(name='ol', version='6', like_distro='centos'),
        DistroNamespace(name='ol', version='6.5', like_distro='centos'),
        DistroNamespace(name='ol', version='7.3', like_distro='centos'),
        DistroNamespace(name='rhel', version='7.1', like_distro='centos'),

        DistroNamespace(name='debian', version='7', like_distro='debian'),
        DistroNamespace(name='debian', version='8', like_distro='debian'),
        DistroNamespace(name='debian', version='9', like_distro='debian'),
        DistroNamespace(name='debian', version='unstable', like_distro='debian'),

        DistroNamespace(name='ubuntu', version='12.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='13.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='14.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='14.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='15.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='15.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='16.04', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='16.10', like_distro='ubuntu'),
        DistroNamespace(name='ubuntu', version='17.04', like_distro='ubuntu'),
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
        if not vulnerabilities.have_vulnerabilities_for(i):
            raise Exception('Bad failure: {}'.format(i.namespace_name))

    for i in fail:
        if vulnerabilities.have_vulnerabilities_for(i):
            raise Exception('Should not have data for {}'.format(i.namespace_name))


def check_fix_version():
    log.info('Checking fix versions')
    db = get_thread_scoped_session()
    img = db.query(Image).get((test_image_ids['node'], '0'))
    vulns = img.vulnerabilities()
    for vuln in vulns:
        if vuln.vulnerability.fixed_in:
            fixes_in = [x for x in vuln.vulnerability.fixed_in if x.name == vuln.pkg_name or x.name == vuln.package.normalized_src_pkg]
            fix_available_in = fixes_in[0].version if fixes_in else 'None'
        else:
            fix_available_in = 'None'
        log.info('{} Fix version: {}'.format(vuln.vulnerability_id, fix_available_in))

def rescan_cve(img_id):
    return get_image_vulnerabilities(user_id='0', image_id=img_id, force_refresh=True)

def run_vuln_test():
    init_db_persisted()
    sync_feeds(up_to=datetime.datetime(2017, 0o6, 0o1))
    load_images()
    check_vuln()

    db = get_thread_scoped_session()
    try:
        f = reset_feed_sync_time(db, datetime.datetime(2017, 0o6, 0o1), feed_name='vulnerabilities')
        db.add(f)
        db.commit()
    except:
        log.exception('Exception commiting update of feed sync timestamps')
        db.rollback()

    sync_feeds(up_to=datetime.datetime.utcnow())
    check_fix_version()
    rescan_img_id = list(test_env.image_map.keys())[0]
    import json
    print((json.dumps(get_image_vulnerabilities(user_id='0', image_id='7b3dce19c46b752708da38a602decbb1cc4906c8c1f1a19b620158926c199930'), indent=2)))
    rescan_cve('7b3dce19c46b752708da38a602decbb1cc4906c8c1f1a19b620158926c199930')

if __name__ == '__main__':
    #run_vuln_test()
    namespace_support_test()
