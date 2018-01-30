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

servicename = 'policy_engine'
temp_logger = None

# service funcs (must be here)
def createService(sname, config):
    from anchore_engine.services.policy_engine.application import application as flask_app
    global monitor_threads, monitors, servicename

    try:
        myconfig = config['services'][sname]
        servicename = sname
    except Exception as err:
        raise err

    try:
        kick_timer = int(myconfig['cycle_timer_seconds'])
    except:
        kick_timer = 1

    doapi = False
    try:
        if myconfig['listen'] and myconfig['port'] and myconfig['endpoint_hostname']:
            doapi = True
    except:
        doapi = False

    kwargs = {}
    kwargs['kick_timer'] = kick_timer
    kwargs['monitors'] = monitors
    kwargs['monitor_threads'] = monitor_threads
    kwargs['servicename'] = servicename

    if doapi:
        # start up flask service

        flask_site = WSGIResource(reactor, reactor.getThreadPool(), flask_app)
        root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
        ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

        # start up the monitor as a looping call
        lc = LoopingCall(anchore_engine.services.common.monitor, **kwargs)
        lc.start(1)
    else:
        # start up the monitor as a timer service
        svc = internet.TimerService(1, anchore_engine.services.common.monitor, **kwargs)
        svc.setName(sname)
        ret_svc = svc

    return (ret_svc)

#    flask_site = WSGIResource(reactor, reactor.getThreadPool(), application)
#    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
#    ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

#    # start up the monitor as a looping call
#    kwargs = {'kick_timer': 1}
#    lc = LoopingCall(anchore_engine.services.policy_engine.monitor, **kwargs)
#    lc.start(1)

#    return (ret_svc)


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
    reg_return = anchore_engine.services.common.registerService(sname, config, enforce_unique=False)
    logger.info('Registration complete.')

    #if reg_return:
    #    process_preflight()

    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=False, detail={'service_state': anchore_engine.subsys.taskstate.complete_state('policy_engine_state')}, update_db=True)

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
    #task = FeedsUpdateTask(feeds_to_sync=feeds)
    task = InitialFeedSyncTask(feeds_to_sync=feeds)
    task.execute()

    return True


def _init_db_content():
    """
    Initialize the policy engine db with any data necessary at startup.

    :return:
    """
    return _init_distro_mappings() and _init_feeds()


#click = 0
initial_sync = False

def handle_bootstrapper(*args, **kwargs):
    global initial_sync, servicename

    cycle_timer = kwargs['mythread']['cycle_timer']

    localconfig = anchore_engine.configuration.localconfig.get_config()
    service_record = {'hostid': localconfig['host_id'], 'servicename': servicename}

    while(True):
        try:
            if not initial_sync:
                try:
                    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=False, message="running initial feed sync", detail={'service_state': anchore_engine.subsys.taskstate.working_state('policy_engine_state')}, update_db=True)
                except Exception as err:
                    logger.error("error setting service status - exception: " + str(err))

                logger.debug("running bootstrap preflight")
                process_preflight()

                try:
                    logger.debug("setting available statue to true")
                    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, detail={'service_state': anchore_engine.subsys.taskstate.complete_state('policy_engine_state')}, update_db=True)
                except Exception as err:
                    logger.error("error setting service status - exception: " + str(err))

                initial_sync = True
        except:
            logger.warn("failed to bootstrap, will retry")

        time.sleep(cycle_timer)
    return(True)

# monitor infrastructure

monitors = {
    'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [servicename], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'feed_sync_bootstrapper': {'handler': handle_bootstrapper, 'taskType': 'handle_bootstrapper', 'args': [], 'cycle_timer': 1, 'min_cycle_timer': 1, 'max_cycle_timer': 120, 'last_queued': 0, 'last_return': False, 'initialized': False},
}
monitor_threads = {}

