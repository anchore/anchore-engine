import datetime
import threading
import json
import time
import sys
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.internet.task import LoopingCall

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.taskstate
import anchore_engine.clients.catalog
from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig


temp_logger = None
click = 0
initial_sync = False

def monitor_func(**kwargs):
    global initial_sync, click

    if click < 5:
        click = click + 1
        logger.debug("policy_engine_monitor starting in: " + str(5 - click))
        return (True)

    logger.debug("FIRING: policy_engine_monitor")
    localconfig = anchore_engine.configuration.localconfig.get_config()
    system_user_auth = localconfig['system_user_auth']
    service_record = {'hostid': localconfig['host_id'], 'servicename': 'policy_engine'}

    if not initial_sync:
        try:
            anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=False, message="running initial feed sync", detail={'service_state': anchore_engine.subsys.taskstate.working_state('policy_engine_state')}, update_db=True)
        except Exception as err:
            logger.error("error setting service status - exception: " + str(err))

        logger.debug("running bootstrap preflight")
        process_preflight()
    try:
        anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, detail={'service_state': anchore_engine.subsys.taskstate.complete_state('policy_engine_state')}, update_db=True)
    except Exception as err:
        logger.error("error setting service status - exception: " + str(err))

    initial_sync = True
    logger.debug("FIRING DONE: policy_engine_monitor")

monitor_thread = None
def monitor(**kwargs):
    global monitor_thread
    try:
        donew = False
        if monitor_thread:
            if monitor_thread.isAlive():
                logger.spew("MON: thread still running")
            else:
                logger.spew("MON: thread stopped running")
                donew = True
                monitor_thread.join()
                logger.spew("MON: thread joined: " + str(monitor_thread.isAlive()))
        else:
            logger.spew("MON: no thread")
            donew = True

        if donew:
            logger.spew("MON: starting")
            monitor_thread = threading.Thread(target=monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))


# service funcs (must be here)
def createService(sname, config):
    from anchore_engine.services.policy_engine.application import application
    flask_site = WSGIResource(reactor, reactor.getThreadPool(), application)
    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
    ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

    # start up the monitor as a looping call
    #kwargs = {'kick_timer': 1}
    #lc = LoopingCall(anchore_engine.services.policy_engine.monitor, **kwargs)
    #lc.start(1)

    return (ret_svc)


def initializeService(sname, config):
    service_record = {'hostid': config['host_id'], 'servicename': sname}
    try:
        if not anchore_engine.subsys.servicestatus.has_status(service_record):
            anchore_engine.subsys.servicestatus.initialize_status(service_record, up=True, available=False, message='initializing')
    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("could not initialize service status - exception: " + str(err))

    return anchore_engine.services.common.initializeService(sname, config)


def registerService(sname, config):
    reg_return = anchore_engine.services.common.registerService(sname, config, enforce_unique=True)
    logger.info('Registration complete.')

    if reg_return:
        process_preflight()

    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, detail={'service_state': anchore_engine.subsys.taskstate.complete_state('policy_engine_state')}, update_db=True)

    return reg_return


def _check_feed_client_credentials():
    from anchore_engine.clients.feeds.feed_service.feeds import get_client
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
    from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask, InitialFeedSyncTask


    feeds = feeds.get_selected_feeds_to_sync(localconfig.get_config())
    task = InitialFeedSyncTask(feeds_to_sync=feeds)
    task.execute()

    return True


def _init_db_content():
    """
    Initialize the policy engine db with any data necessary at startup.

    :return:
    """
    return _init_distro_mappings() and _init_feeds()

