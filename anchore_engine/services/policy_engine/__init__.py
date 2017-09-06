import datetime
import sys
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common
from anchore_engine.subsys import logger

temp_logger = None

# service funcs (must be here)
def createService(sname, config):
    from anchore_engine.services.policy_engine.application import application
    flask_site = WSGIResource(reactor, reactor.getThreadPool(), application)
    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
    return (anchore_engine.services.common.createServiceAPI(root, sname, config))


def initializeService(sname, config):
    return anchore_engine.services.common.initializeService(sname, config)


def registerService(sname, config):
    reg_return = anchore_engine.services.common.registerService(sname, config)
    logger.info('Registration complete.')

    if reg_return:
        process_preflight()
    return reg_return


def _check_feed_client_credentials():
    from anchore_engine.clients.feeds.anchore_io.feeds import get_client
    logger.info('Checking feeds client credentials')
    client = get_client()
    client = None
    logger.info('Feeds client credentials ok')


def process_preflight():
    """
    Execute the preflight functions, aborting service startup if any throw uncaught exceptions or return False return value

    :return:
    """
    preflight_check_functions = [
        _check_feed_client_credentials,
        _init_db_content
    ]

    for fn in preflight_check_functions:
        try:
            fn()
        except Exception as e:
            logger.error('Preflight checks failed with error: {}. Aborting service startup'.format(e))
            sys.exit(1)


def _init_distro_mappings():
    from anchore_engine.db import session_scope, DistroMapping

    initial_mappings = [
        DistroMapping(from_distro='alpine', to_distro='alpine', flavor='ALPINE'),
        DistroMapping(from_distro='busybox', to_distro='busybox', flavor='BUSYB'),
        DistroMapping(from_distro='centos', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='debian', to_distro='debian', flavor='DEB'),
        DistroMapping(from_distro='fedora', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='ol', to_distro='ol', flavor='RHEL'),
        DistroMapping(from_distro='rhel', to_distro='centos', flavor='RHEL'),
        DistroMapping(from_distro='ubuntu', to_distro='ubuntu', flavor='DEB')
    ]

    # set up any data necessary at system init
    try:
        logger.info('Checking policy engine db initialization. Checking initial set of distro mappings')
        with session_scope() as dbsession:
            distro_mappings = dbsession.query(DistroMapping).all()

            for i in initial_mappings:
                if not filter(lambda x: x.from_distro == i.from_distro, distro_mappings):
                    logger.info('Adding missing mapping: {}'.format(i))
                    dbsession.add(i)

        logger.info('Distro mapping initialization complete')
    except Exception as err:
        raise Exception("unable to initialize default distro mappings - exception: " + str(err))

    return True


def _init_feeds():
    """
    Perform an initial feed sync using a bulk-sync if no sync has been done yet.

    :return:
    """

    image_count_bulk_sync_threshold = 0 # More than this many images will result in the system doing a regular sync instead of a bulk sync.

    logger.info('Initializing feeds if necessary')
    from anchore_engine.services.policy_engine.engine import vulnerabilities, feeds
    from anchore_engine.db import Image, session_scope
    from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask
    from anchore_engine.services.policy_engine.engine.feeds import InsufficientAccessTierError, InvalidCredentialsError

    if feeds.DataFeeds.instance().vulnerabilities.never_synced():
        logger.info('Detected that vulnerability feed has never been synced. Now checking for loaded images')
        with session_scope() as dbsession:
            image_count = dbsession.query(Image).count()
            logger.info('Detected {} images in the policy engine db. Threshold is {} for a bulk sync'.format(image_count, image_count_bulk_sync_threshold))
            if image_count <= image_count_bulk_sync_threshold:
                logger.info('Performing bulk sync')
                try:
                    feeds.DataFeeds.instance().vulnerabilities.bulk_sync()
                except Exception as e:
                    logger.exception('Exception thrown during bulk sync of vulnerabilities feed. Failing service initialization')
                    raise e

                if image_count > 0:
                    for image in dbsession.query(Image).all():
                        logger.info('Checking image {}/{} for vulnerabilities'.format(image.user_id, image.id))
                        vulns = vulnerabilities.vulnerabilities_for_image(image)
                        logger.info('Found {} vulnerability matches for image {}/{}'.format(len(vulns), image.user_id, image.id))
                        for v in vulns:
                            dbsession.add(v)
                    logger.info('Vulnerability scan of already-loaded images complete')
            else:
                logger.info('Performing regular sync, this could take a while')
                task = FeedsUpdateTask(created_at=datetime.datetime.utcnow())
                result = task.execute()
                if result:
                    updated_image_count = reduce(lambda x, y: x + len(y), result.values(), 0)
                else:
                    updated_image_count = 0
                logger.info('Feed sync task completed with {} image vulnerability match updates'.format(updated_image_count))
    else:
        logger.info('Previous vulnerability feed sync detected, skipping initial sync.')

    # if feeds.DataFeeds.instance().packages.never_synced():
    #     logger.info('Detected that packages feed never been synced. Performing initial sync.')
    #     try:
    #         feeds.DataFeeds.instance().packages.bulk_sync()
    #     except InsufficientAccessTierError as e:
    #         logger.warn('Skipping packages sync: {}'.format(e))
    #     except Exception as e:
    #         logger.exception(
    #             'Exception thrown during bulk sync of vulnerabilities feed. Failing service initialization')
    #         raise e
    # else:
    #     logger.info('Detected previous packages feed sync, skipping initial sync.')

    return True


def _init_db_content():
    """
    Initialize the policy engine db with any data necessary at startup.

    :return:
    """
    return _init_distro_mappings() and _init_feeds()

