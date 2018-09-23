import time
import sys

# anchore modules
#import anchore_engine.services.common
import anchore_engine.clients.common
import anchore_engine.subsys.servicestatus
#import anchore_engine.subsys.taskstate
import anchore_engine.subsys.metrics
#import anchore_engine.clients.catalog
from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig
from anchore_engine.clients import simplequeue
from anchore_engine.service import ApiService, LifeCycleStages

feed_sync_queuename = 'feed_sync_tasks'
system_user_auth = None
feed_sync_msg = {
    'task_type': 'feed_sync',
    'enabled': True
}

# service funcs (must be here)

def _check_feed_client_credentials():
    from anchore_engine.clients.feeds.feed_service import get_client
    logger.info('Checking feeds client credentials')
    client = get_client()
    client = None
    logger.info('Feeds client credentials ok')


def _system_creds():
    global system_user_auth

    if not system_user_auth:
        config = localconfig.get_config()
        system_user_auth = config['system_user_auth']

    return system_user_auth


def process_preflight():
    """
    Execute the preflight functions, aborting service startup if any throw uncaught exceptions or return False return value

    :return:
    """

    config = localconfig.get_config()

    # read the global feed disable parameter
    feed_sync_enabled = config.get('feeds', {}).get('sync_enabled', True)

    # get the list of feeds if they have been explicitly configured in config.yaml
    feed_enabled_status = config.get('feeds', {}).get('selective_sync', {}).get('feeds', {})

    # check to see if the engine is configured to sync at least one data feed
    at_least_one = False
    for feed in feed_enabled_status.keys():
        if feed_enabled_status[feed]:
            at_least_one = True
            break

    # toggle credential validation based on whether or not any feeds are configured to sync
    skip_credential_validate = False
    if not feed_sync_enabled or not at_least_one:
        logger.info("Engine is configured to skip data feed syncs - skipping feed sync client check")
        skip_credential_validate = True

    preflight_check_functions = [_init_db_content]
    if not skip_credential_validate:
        preflight_check_functions.append(_check_feed_client_credentials)

    for fn in preflight_check_functions:
        try:
            fn()
        except Exception as e:
            logger.exception('Preflight checks failed with error: {}. Aborting service startup'.format(e))
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
        DistroMapping(from_distro='ubuntu', to_distro='ubuntu', flavor='DEB'),
        #DistroMapping(from_distro='java', to_distro='snyk', flavor='JAVA'),
        #DistroMapping(from_distro='gem', to_distro='snyk', flavor='RUBY'),
        #DistroMapping(from_distro='npm', to_distro='snyk', flavor='NODEJS'),
        #DistroMapping(from_distro='python', to_distro='snyk', flavor='PYTHON'),
    ]

    # set up any data necessary at system init
    try:
        logger.info('Checking policy engine db initialization. Checking initial set of distro mappings')
        with session_scope() as dbsession:
            distro_mappings = dbsession.query(DistroMapping).all()

            for i in initial_mappings:
                if not [x for x in distro_mappings if x.from_distro == i.from_distro]:
                    logger.info('Adding missing mapping: {}'.format(i))
                    dbsession.add(i)

        logger.info('Distro mapping initialization complete')
    except Exception as err:
        raise Exception("unable to initialize default distro mappings - exception: " + str(err))

    return True


def _init_db_content():
    """
    Initialize the policy engine db with any data necessary at startup.

    :return:
    """
    return _init_distro_mappings()


def do_feed_sync(msg):
    if 'FeedsUpdateTask' not in locals():
        from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask

    if 'get_selected_feeds_to_sync' not in locals():
        from anchore_engine.services.policy_engine.engine.feeds import get_selected_feeds_to_sync

    handler_success = False
    timer = time.time()
    logger.info("FIRING: feed syncer")
    try:
        feeds = get_selected_feeds_to_sync(localconfig.get_config())
        logger.info('Syncing configured feeds: {}'.format(feeds))
        result = FeedsUpdateTask.run_feeds_update(json_obj=msg.get('data'))

        if result is not None:
            handler_success = True
        else:
            logger.warn('Feed sync task marked as disabled, so skipping')
    except ValueError as e:
        logger.warn('Received msg of wrong type')
    except Exception as err:
        logger.warn("failure in feed sync handler - exception: " + str(err))

    if handler_success:
        anchore_engine.subsys.metrics.summary_observe('anchore_monitor_runtime_seconds', time.time() - timer, function='do_feed_sync', status="success")
    else:
        anchore_engine.subsys.metrics.summary_observe('anchore_monitor_runtime_seconds', time.time() - timer, function='do_feed_sync', status="fail")


def handle_feed_sync(*args, **kwargs):
    """
    Initiates a feed sync in the system in response to a message from the queue

    :param args:
    :param kwargs:
    :return:
    """
    system_user = _system_creds()

    logger.info('init args: {}'.format(kwargs))
    cycle_time = kwargs['mythread']['cycle_timer']

    while True:

        config = localconfig.get_config()
        feed_sync_enabled = config.get('feeds', {}).get('sync_enabled', True)

        if feed_sync_enabled:
            try:
                all_ready = anchore_engine.clients.common.check_services_ready(['simplequeue'])
                if not all_ready:
                    logger.info("simplequeue service not yet ready, will retry")
                else:
                    try:
                        simplequeue.run_target_with_queue_ttl(system_user, queue=feed_sync_queuename, target=do_feed_sync, max_wait_seconds=30, visibility_timeout=180)
                    except Exception as err:
                        logger.warn("failed to process task this cycle: " + str(err))
            except Exception as e:
                logger.error('Caught escaped error in feed sync handler: {}'.format(e))
        else:
            logger.debug("sync_enabled is set to false in config - skipping feed sync")

        time.sleep(cycle_time)

    return True


def handle_feed_sync_trigger(*args, **kwargs):
    """
    Checks to see if there is a task for a feed sync in the queue and if not, adds one.
    Interval for firing this should be longer than the expected feed sync duration.

    :param args:
    :param kwargs:
    :return:
    """
    system_user = _system_creds()

    logger.info('init args: {}'.format(kwargs))
    cycle_time = kwargs['mythread']['cycle_timer']

    while True:

        config = localconfig.get_config()
        feed_sync_enabled = config.get('feeds', {}).get('sync_enabled', True)

        if feed_sync_enabled:
            try:
                all_ready = anchore_engine.clients.common.check_services_ready(['simplequeue'])
                if not all_ready:
                    logger.info("simplequeue service not yet ready, will retry")
                else:
                    logger.info('Feed Sync Trigger activated')
                    if not simplequeue.is_inqueue(userId=system_user, name=feed_sync_queuename, inobj=feed_sync_msg):
                        try:
                            simplequeue.enqueue(userId=system_user, name=feed_sync_queuename, inobj=feed_sync_msg)
                        except:
                            logger.exception('Could not enqueue message for a feed sync')
                    logger.info('Feed Sync Trigger done, waiting for next cycle.')
            except Exception as e:
                logger.exception('Error caught in feed sync trigger handler. Will continue. Exception: {}'.format(e))
        else:
            logger.debug("sync_enabled is set to false in config - skipping feed sync trigger")

        time.sleep(cycle_time)

    return True


class PolicyEngineService(ApiService):
    __service_name__ = 'policy_engine'
    __spec_dir__ = 'services/policy_engine/swagger'
    __monitors__ = {
        'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [__service_name__], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
        'feed_sync_checker': {'handler': handle_feed_sync_trigger, 'taskType': 'handle_feed_sync_trigger', 'args': [], 'cycle_timer': 600, 'min_cycle_timer': 300, 'max_cycle_timer': 100000, 'last_queued': 0, 'last_return': False, 'initialized': False},
        'feed_sync': {'handler': handle_feed_sync, 'taskType': 'handle_feed_sync', 'args': [], 'cycle_timer': 3600, 'min_cycle_timer': 1800, 'max_cycle_timer': 100000, 'last_queued': 0, 'last_return': False, 'initialized': False}
    }

    __lifecycle_handlers__ = {
        LifeCycleStages.pre_register: [(process_preflight, None)]
    }

    #def _register_instance_handlers(self):
    #    super()._register_instance_handlers()
    #    self.register_handler(LifeCycleStages.pre_register, process_preflight, None)
