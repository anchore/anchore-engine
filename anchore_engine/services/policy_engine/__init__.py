import contextlib
import time
import sys
import pkg_resources
import os

# anchore modules
import anchore_engine.clients.services.common
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig
from anchore_engine.clients.services import simplequeue
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.service import ApiService, LifeCycleStages

# from anchore_engine.subsys.logger import enable_bootstrap_logging
# enable_bootstrap_logging()


feed_sync_queuename = 'feed_sync_tasks'
system_user_auth = None
feed_sync_msg = {
    'task_type': 'feed_sync',
    'enabled': True
}

try:
    feed_config_check_retries = int(os.getenv('FEED_CLIENT_CHECK_RETRIES', 3))
except:
    logger.exception('Error parsing env value FEED_CLIENT_CHECK_RETRIES into int, using default value of 3')
    feed_config_check_retries = 3

try:
    feed_config_check_backoff = int(os.getenv('FEED_CLIENT_CHECK_BACKOFF', 5))
except:
    logger.exception('Error parsing env FEED_CLIENT_CHECK_BACKOFF value into int, using default value of 5')
    feed_config_check_backoff = 5

# service funcs (must be here)

def _check_feed_client_credentials():
    from anchore_engine.clients.feeds.feed_service import get_client
    sleep_time = feed_config_check_backoff
    last_ex = None

    for i in range(feed_config_check_retries):
        if i > 0:
            logger.info("Waiting for {} seconds to try feeds client config check again".format(sleep_time))
            time.sleep(sleep_time)
            sleep_time += feed_config_check_backoff

        try:
            logger.info('Checking feeds client credentials. Attempt {} of {}'.format(i + 1, feed_config_check_retries))
            client = get_client()
            client = None
            logger.info('Feeds client credentials ok')
            return True
        except Exception as e:
            logger.warn("Could not verify feeds endpoint and/or config. Got exception: {}".format(e))
            last_ex = e
    else:
        if last_ex:
            raise last_ex
        else:
            raise Exception('Exceeded retries for feeds client config check. Failing check')

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

    preflight_check_functions = [_init_db_content]

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
        DistroMapping(from_distro='amzn', to_distro='amzn', flavor='RHEL'),
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
                all_ready = anchore_engine.clients.services.common.check_services_ready(['simplequeue'])
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

    retries = int(os.getenv('ANCHORE_FEED_SYNC_CHECK_RETRIES', 5))
    backoff_time = int(os.getenv('ANCHORE_FEED_SYNC_CHECK_FAILURE_BACKOFF', 5))

    while True:
        config = localconfig.get_config()
        feed_sync_enabled = config.get('feeds', {}).get('sync_enabled', True)
        if feed_sync_enabled:
            sleep_time = backoff_time
            for i in range(retries):
                try:
                    all_ready = anchore_engine.clients.services.common.check_services_ready(['simplequeue'])

                    if not all_ready:
                        logger.info("simplequeue service not yet ready, will retry")
                    else:
                        logger.info('Feed Sync Trigger activated')
                        q_client = SimpleQueueClient(user=system_user[0], password=system_user[1])
                        if not q_client.is_inqueue(name=feed_sync_queuename, inobj=feed_sync_msg):
                            try:
                                q_client.enqueue(name=feed_sync_queuename, inobj=feed_sync_msg)
                            except:
                                logger.error('Could not enqueue message for a feed sync')
                                raise

                        logger.info('Feed Sync Trigger done, waiting for next cycle.')
                        break
                except Exception as e:
                    logger.exception('Error caught in feed sync trigger handler. Will backoff {} seconds and retry. Attempt {}. Exception: {}'.format(sleep_time, i, e))

                time.sleep(sleep_time)
                sleep_time += backoff_time
            else:
                logger.info('Exceeded max retries {} to check feed sync queue. Will wait until next duty cycle'.format(retries))

        else:
            logger.debug("sync_enabled is set to false in config - skipping feed sync trigger")

        time.sleep(cycle_time)

    return True


class PolicyEngineService(ApiService):
    __service_name__ = 'policy_engine'
    __spec_dir__ = pkg_resources.resource_filename(__name__, 'swagger')
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
