import os
import sys
import time

import pkg_resources
import retrying
from sqlalchemy.exc import IntegrityError

# anchore modules
import anchore_engine.clients.services.common
import anchore_engine.subsys.metrics
import anchore_engine.subsys.servicestatus
from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton
from anchore_engine.clients.services import internal_client_for, simplequeue
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.models.schemas import BatchImageVulnerabilitiesQueueMessage
from anchore_engine.configuration import localconfig
from anchore_engine.service import ApiService, LifeCycleStages
from anchore_engine.services.policy_engine.engine.feeds import (  # Import grypedb_sync so that class variables are initialized before twistd threads start
    grypedb_sync,
)
from anchore_engine.services.policy_engine.engine.feeds.config import (
    get_provider_name,
    get_section_for_vulnerabilities,
    is_sync_enabled,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import (
    GithubFeed,
    GrypeDBFeed,
    NvdFeed,
    NvdV2Feed,
    PackagesFeed,
    VulnDBFeed,
    VulnerabilityFeed,
    feed_registry,
)
from anchore_engine.subsys import logger

# from anchore_engine.subsys.logger import enable_bootstrap_logging
# enable_bootstrap_logging()

feed_sync_queuename = "feed_sync_tasks"
system_user_auth = None
feed_sync_msg = {"task_type": "feed_sync", "enabled": True}

# These are user-configurable but mostly for debugging and testing purposes
try:
    FEED_SYNC_RETRIES = int(os.getenv("ANCHORE_FEED_SYNC_CHECK_RETRIES", 5))
except ValueError:
    logger.exception(
        "Error parsing env value ANCHORE_FEED_SYNC_CHECK_RETRIES into int, using default value of 5"
    )
    FEED_SYNC_RETRIES = 5

try:
    FEED_SYNC_RETRY_BACKOFF = int(
        os.getenv("ANCHORE_FEED_SYNC_CHECK_FAILURE_BACKOFF", 5)
    )
except ValueError:
    logger.exception(
        "Error parsing env value ANCHORE_FEED_SYNC_CHECK_FAILURE_BACKOFF into int, using default value of 5"
    )
    FEED_SYNC_RETRY_BACKOFF = 5

try:
    feed_config_check_retries = int(os.getenv("FEED_CLIENT_CHECK_RETRIES", 3))
except ValueError:
    logger.exception(
        "Error parsing env value FEED_CLIENT_CHECK_RETRIES into int, using default value of 3"
    )
    feed_config_check_retries = 3

try:
    feed_config_check_backoff = int(os.getenv("FEED_CLIENT_CHECK_BACKOFF", 5))
except ValueError:
    logger.exception(
        "Error parsing env FEED_CLIENT_CHECK_BACKOFF value into int, using default value of 5"
    )
    feed_config_check_backoff = 5

# service funcs (must be here)


def _system_creds():
    global system_user_auth

    if not system_user_auth:
        config = localconfig.get_config()
        system_user_auth = config["system_user_auth"]

    return system_user_auth


def process_preflight():
    """
    Execute the preflight functions, aborting service startup if any throw uncaught exceptions or return False return value

    :return:
    """

    preflight_check_functions = [init_db_content, init_feed_registry]

    for fn in preflight_check_functions:
        try:
            fn()
        except Exception as e:
            logger.exception(
                "Preflight checks failed with error: {}. Aborting service startup".format(
                    e
                )
            )
            sys.exit(1)


def _init_distro_mappings():
    from anchore_engine.db import DistroMapping, session_scope

    initial_mappings = [
        DistroMapping(from_distro="alpine", to_distro="alpine", flavor="ALPINE"),
        DistroMapping(from_distro="busybox", to_distro="busybox", flavor="BUSYB"),
        DistroMapping(from_distro="centos", to_distro="rhel", flavor="RHEL"),
        DistroMapping(from_distro="debian", to_distro="debian", flavor="DEB"),
        DistroMapping(from_distro="fedora", to_distro="rhel", flavor="RHEL"),
        DistroMapping(from_distro="ol", to_distro="ol", flavor="RHEL"),
        DistroMapping(from_distro="rhel", to_distro="rhel", flavor="RHEL"),
        DistroMapping(from_distro="ubuntu", to_distro="ubuntu", flavor="DEB"),
        DistroMapping(from_distro="amzn", to_distro="amzn", flavor="RHEL"),
        DistroMapping(from_distro="redhat", to_distro="rhel", flavor="RHEL"),
    ]

    # set up any data necessary at system init
    try:
        logger.info(
            "Checking policy engine db initialization. Checking initial set of distro mappings"
        )

        with session_scope() as dbsession:
            distro_mappings = dbsession.query(DistroMapping).all()

            for i in initial_mappings:
                if not [x for x in distro_mappings if x.from_distro == i.from_distro]:
                    logger.info("Adding missing mapping: {}".format(i))
                    dbsession.add(i)

        logger.info("Distro mapping initialization complete")
    except Exception as err:

        if isinstance(err, IntegrityError):
            logger.warn("another process has already initialized, continuing")
        else:
            raise Exception(
                "unable to initialize default distro mappings - exception: " + str(err)
            )

    return True


def init_db_content():
    """
    Initialize the policy engine db with any data necessary at startup.

    :return:
    """
    return _init_distro_mappings()


def init_feed_registry():
    # Register feeds, the tuple is the class and bool if feed is a distro vulnerability feed or not
    for cls_tuple in [
        (NvdV2Feed, False),
        (VulnDBFeed, False),
        (VulnerabilityFeed, True),
        (PackagesFeed, False),
        (GithubFeed, False),
        (NvdFeed, False),
        (GrypeDBFeed, True),
    ]:
        logger.info("Registering feed handler {}".format(cls_tuple[0].__feed_name__))
        feed_registry.register(cls_tuple[0], is_vulnerability_feed=cls_tuple[1])


def do_feed_sync(msg):
    if "FeedsUpdateTask" not in locals():
        from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask

    handler_success = False
    timer = time.time()
    logger.info("FIRING: feed syncer")
    try:
        result = FeedsUpdateTask.run_feeds_update(json_obj=msg.get("data"))

        if result is not None:
            handler_success = True
        else:
            logger.warn("Feed sync task marked as disabled, so skipping")
    except ValueError as e:
        logger.warn("Received msg of wrong type")
    except Exception as err:
        logger.warn("failure in feed sync handler - exception: " + str(err))

    if handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function="do_feed_sync",
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function="do_feed_sync",
            status="fail",
        )


def handle_feed_sync(*args, **kwargs):
    """
    Initiates a feed sync in the system in response to a message from the queue

    :param args:
    :param kwargs:
    :return:
    """
    system_user = _system_creds()

    logger.info("init args: {}".format(kwargs))
    cycle_time = kwargs["mythread"]["cycle_timer"]

    while True:
        config = get_section_for_vulnerabilities()
        feed_sync_enabled = is_sync_enabled(config)
        if feed_sync_enabled:
            logger.info("Feed sync task executor activated")
            try:
                run_feed_sync(system_user)
            except Exception as e:
                logger.error("Caught escaped error in feed sync handler: {}".format(e))
            finally:
                logger.info("Feed sync task executor complete")
        else:
            logger.info("sync enabled is set to false in config - skipping feed sync")

        time.sleep(cycle_time)

    return True


@retrying.retry(
    stop_max_attempt_number=FEED_SYNC_RETRIES,
    wait_incrementing_start=FEED_SYNC_RETRY_BACKOFF * 1000,
    wait_incrementing_increment=FEED_SYNC_RETRY_BACKOFF * 1000,
)
def run_feed_sync(system_user):
    all_ready = anchore_engine.clients.services.common.check_services_ready(
        ["simplequeue"]
    )
    if not all_ready:
        logger.info("simplequeue service not yet ready, will retry")
        raise Exception("Simplequeue service not yet ready")
    else:
        try:
            # This has its own retry on the queue fetch, so wrap with catch block to ensure we don't double-retry on task exec
            simplequeue.run_target_with_queue_ttl(
                None,
                queue=feed_sync_queuename,
                target=do_feed_sync,
                max_wait_seconds=30,
                visibility_timeout=180,
                retries=FEED_SYNC_RETRIES,
                backoff_time=FEED_SYNC_RETRY_BACKOFF,
            )
        except Exception as err:
            logger.warn("failed to process task this cycle: " + str(err))


def handle_feed_sync_trigger(*args, **kwargs):
    """
    Checks to see if there is a task for a feed sync in the queue and if not, adds one.
    Interval for firing this should be longer than the expected feed sync duration.

    :param args:
    :param kwargs:
    :return:
    """
    system_user = _system_creds()

    logger.info("init args: {}".format(kwargs))
    cycle_time = kwargs["mythread"]["cycle_timer"]

    while True:
        config = get_section_for_vulnerabilities()
        feed_sync_enabled = is_sync_enabled(config)
        if feed_sync_enabled:
            logger.info("Feed Sync task creator activated")
            try:
                push_sync_task(system_user)
                logger.info("Feed Sync Trigger done, waiting for next cycle.")
            except Exception as e:
                logger.error(
                    "Error caught in feed sync trigger handler after all retries. Will wait for next cycle"
                )
            finally:
                logger.info("Feed Sync task creator complete")
        else:
            logger.info(
                "sync_enabled is set to false in config - skipping feed sync trigger"
            )

        time.sleep(cycle_time)

    return True


def handle_grypedb_sync(*args, **kwargs):
    """
    Calls function to run GrypeDBSyncTask

    :param args:
    :param kwargs:
    :return:
    """
    # import code in function so that it is not imported to all contexts that import policy engine
    # this is an issue caused by these handlers being declared within the __init__.py file
    # See https://github.com/anchore/anchore-engine/issues/991
    from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
        GrypeDBSyncError,
    )
    from anchore_engine.services.policy_engine.engine.tasks import GrypeDBSyncTask

    logger.info("init args: {}".format(kwargs))
    cycle_time = kwargs["mythread"]["cycle_timer"]

    while True:
        provider = get_provider_name(get_section_for_vulnerabilities())
        if provider == "grype":  # TODO fix this
            try:
                GrypeDBSyncTask().execute()
            # TODO narrow scope of exceptions in handlers. see https://github.com/anchore/anchore-engine/issues/1005
            except Exception:
                logger.exception(
                    "Error encountered when running GrypeDBSyncTask from async monitor"
                )
        else:
            logger.debug(
                "Grype DB sync not supported for vulnerabilities provider %s, skipping",
                provider,
            )
        time.sleep(cycle_time)
    return True


@retrying.retry(
    stop_max_attempt_number=FEED_SYNC_RETRIES,
    wait_incrementing_start=FEED_SYNC_RETRY_BACKOFF * 1000,
    wait_incrementing_increment=FEED_SYNC_RETRY_BACKOFF * 1000,
)
def push_sync_task(system_user):
    all_ready = anchore_engine.clients.services.common.check_services_ready(
        ["simplequeue"]
    )

    if not all_ready:
        logger.info("simplequeue service not yet ready, will retry")
        raise Exception("Simplequeue service not yet ready")
    else:
        # q_client = SimpleQueueClient(user=system_user[0], password=system_user[1])
        q_client = internal_client_for(SimpleQueueClient, userId=None)
        if not q_client.is_inqueue(name=feed_sync_queuename, inobj=feed_sync_msg):
            try:
                q_client.enqueue(name=feed_sync_queuename, inobj=feed_sync_msg)
            except:
                logger.error("Could not enqueue message for a feed sync")
                raise


def handle_image_vulnerabilities_refresh(*args, **kwargs):
    """
    Checks the queue for any refresh tasks and calls the provider
    """
    # import code in function so that it is not imported to all contexts that import policy engine
    # this is an issue caused by these handlers being declared within the __init__.py file
    # See https://github.com/anchore/anchore-engine/issues/991
    from anchore_engine.services.policy_engine.engine.tasks import (
        ImageVulnerabilitiesRefreshTask,
    )

    logger.info("init args: {}".format(kwargs))
    cycle_time = kwargs["mythread"]["cycle_timer"]

    queue_name = "image_vulnerabilities"

    while True:
        try:
            all_ready = anchore_engine.clients.services.common.check_services_ready(
                ["simplequeue"]
            )

            if all_ready:
                q_client = internal_client_for(SimpleQueueClient, userId=None)
                qlen = q_client.qlen(name=queue_name)
                while qlen > 0:
                    try:
                        logger.debug("Found %s task(s) in %s queue", qlen, queue_name)
                        queue_message = q_client.dequeue(name=queue_name)

                        if not queue_message:
                            logger.warn(
                                "Received an invalid/empty message from %s queue %s",
                                queue_name,
                                queue_message,
                            )
                            continue

                        try:
                            batch_request = (
                                BatchImageVulnerabilitiesQueueMessage.from_json(
                                    queue_message.get("data")
                                )
                            )
                        except:
                            logger.exception(
                                "Ignoring error parsing %s queue message %s",
                                queue_name,
                                queue_message,
                            )
                            continue

                        for message in batch_request.messages:
                            try:
                                ImageVulnerabilitiesRefreshTask(message).execute()
                            except:
                                logger.exception(
                                    "Failed to refresh image vulnerabilities report"
                                )
                    finally:
                        qlen = q_client.qlen(name=queue_name)

            else:
                logger.info("simplequeue service not yet ready, will retry")
        except:
            logger.exception(
                "Unexpected error in image vulnerabilities refresh handler, will retry"
            )

        time.sleep(cycle_time)

    return True


def initialize_grype_wrapper():
    logger.debug("Initializing Grype wrapper singleton.")
    GrypeWrapperSingleton.get_instance()
    logger.debug("Grype wrapper initialized.")


class PolicyEngineService(ApiService):
    __service_name__ = "policy_engine"
    __spec_dir__ = pkg_resources.resource_filename(__name__, "swagger")
    __monitors__ = {
        "service_heartbeat": {
            "handler": anchore_engine.subsys.servicestatus.handle_service_heartbeat,
            "taskType": "handle_service_heartbeat",
            "args": [__service_name__],
            "cycle_timer": 60,
            "min_cycle_timer": 60,
            "max_cycle_timer": 60,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "feed_sync_checker": {
            "handler": handle_feed_sync_trigger,
            "taskType": "handle_feed_sync_trigger",
            "args": [],
            "cycle_timer": 600,
            "min_cycle_timer": 300,
            "max_cycle_timer": 100000,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "feed_sync": {
            "handler": handle_feed_sync,
            "taskType": "handle_feed_sync",
            "args": [],
            "cycle_timer": 3600,
            "min_cycle_timer": 1800,
            "max_cycle_timer": 100000,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "grypedb_sync": {
            "handler": handle_grypedb_sync,
            "taskType": "handle_grypedb_sync",
            "args": [],
            "cycle_timer": 60,
            "min_cycle_timer": 60,
            "max_cycle_timer": 3600,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "image_vulnerabilities_refresh": {
            "handler": handle_image_vulnerabilities_refresh,
            "taskType": "image_vulnerabilities_refresh",
            "args": [],
            "cycle_timer": 600,
            "min_cycle_timer": 60,
            "max_cycle_timer": 86400,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
    }

    __lifecycle_handlers__ = {
        LifeCycleStages.pre_register: [
            (process_preflight, None),
        ],
        LifeCycleStages.post_bootstrap: [
            (initialize_grype_wrapper, None),
        ],
    }
