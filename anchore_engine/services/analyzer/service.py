import copy
import os
import time

import pkg_resources

import anchore_engine.subsys
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.models.schemas import (
    AnalysisQueueMessage,
    ImportQueueMessage,
    QueueMessage,
)
from anchore_engine.configuration import localconfig
from anchore_engine.service import ApiService
from anchore_engine.services.analyzer.analysis import (
    ImageAnalysisTask,
    is_analysis_message,
)
from anchore_engine.services.analyzer.config import (
    PACKAGE_FILTERING_ENABLED_KEY,
    get_bool_value,
)
from anchore_engine.services.analyzer.imports import ImportTask, is_import_message
from anchore_engine.services.analyzer.layer_cache import handle_layer_cache
from anchore_engine.services.analyzer.tasks import WorkerTask
from anchore_engine.subsys import logger, metrics

IMAGE_ANALYSIS_QUEUE = "images_to_analyze"


class UnexpectedTaskTypeError(Exception):
    def __init__(self, message: QueueMessage):
        super().__init__(
            "Retrieved message from queue of unexpected content/type: {}".format(
                message.to_json_str()
            )
        )


def handle_metrics(*args, **kwargs):
    """
    Update resource usage metrics

    :param args:
    :param kwargs:
    :return:
    """
    cycle_timer = kwargs["mythread"]["cycle_timer"]

    while True:
        try:
            conf = localconfig.get_config()
            try:
                tmpdir = conf["tmp_dir"]
                svfs = os.statvfs(tmpdir)
                available_bytes = svfs.f_bsize * svfs.f_bavail
                metrics.gauge_set("anchore_tmpspace_available_bytes", available_bytes)
            except Exception as err:
                logger.warn(
                    "unable to detect available bytes probe - exception: " + str(err)
                )
        except Exception as err:
            logger.warn("handler failed - exception: " + str(err))

        time.sleep(cycle_timer)

    return True


def build_task(message: QueueMessage, config: dict) -> WorkerTask:
    owned_package_filtering_enabled = get_bool_value(
        config.get(PACKAGE_FILTERING_ENABLED_KEY, "true")
    )
    if is_analysis_message(message.data):
        logger.info("Starting image analysis thread")
        return ImageAnalysisTask(
            AnalysisQueueMessage.from_json(message.data),
            layer_cache_enabled=config.get("layer_cache_enable", False),
            owned_package_filtering_enabled=owned_package_filtering_enabled,
        )
    elif is_import_message(message.data):
        logger.info("Starting image import thread")
        return ImportTask(
            ImportQueueMessage.from_json(message.data),
            owned_package_filtering_enabled=owned_package_filtering_enabled,
        )
    else:
        raise UnexpectedTaskTypeError(message)


def handle_image_analyzer(*args, **kwargs):
    """
    Processor for image analysis requests coming from the work queue

    :param args:
    :param kwargs:
    :return:
    """

    cycle_timer = kwargs["mythread"]["cycle_timer"]

    config = localconfig.get_config()
    myconfig = config["services"]["analyzer"]
    max_analyze_threads = int(myconfig.get("max_threads", 1))
    layer_cache_enable = myconfig.get("layer_cache_enable", False)
    logger.debug("max analysis threads: " + str(max_analyze_threads))

    threads = []
    layer_cache_dirty = True

    while True:
        logger.debug("analyzer thread cycle start")
        try:
            q_client = internal_client_for(SimpleQueueClient, userId=None)

            if len(threads) < max_analyze_threads:
                logger.debug(
                    "analyzer has free worker threads {} / {}".format(
                        len(threads), max_analyze_threads
                    )
                )
                qobj = q_client.dequeue(IMAGE_ANALYSIS_QUEUE)
                if qobj:
                    myqobj = copy.deepcopy(qobj)
                    logger.debug(
                        "got work from queue task Id: {}".format(
                            qobj.get("queueId", "unknown")
                        )
                    )
                    logger.debug(
                        "incoming queue object: " + str(myqobj)
                    )  # Was "spew" level

                    message = QueueMessage.from_json(qobj)
                    task = build_task(message, myconfig)
                    task.start()
                    threads.append(task)
                    logger.debug("thread started")

                    # Only analysis tasks can dirty the cache, import or other tasks don't use it
                    if type(task) == ImageAnalysisTask:
                        layer_cache_dirty = True

                else:
                    logger.debug("analyzer queue is empty - no work this cycle")
            else:
                logger.debug("all workers are busy")

            alive_threads = []
            while threads:
                athread = threads.pop()
                if not athread.is_alive():
                    try:
                        logger.debug("thread completed - joining")
                        athread.join()
                        logger.info("worker thread completed")
                    except Exception as err:
                        logger.warn("cannot join thread - exception: " + str(err))
                else:
                    alive_threads.append(athread)
            threads = alive_threads

            # TODO: would like to fold this into the ImageAnalysisTask thread, but this basically assumes a mutex. Can add RLock later
            if layer_cache_enable and layer_cache_dirty and len(threads) == 0:
                logger.debug("running layer cache handler")
                try:
                    handle_layer_cache()
                    layer_cache_dirty = False
                except Exception as err:
                    logger.warn(
                        "layer cache management failed - exception: " + str(err)
                    )

        except Exception as err:
            logger.exception("Failure in image analysis loop")

        logger.debug("analyzer thread cycle complete: next in " + str(cycle_timer))
        time.sleep(cycle_timer)

    return True


class AnalyzerService(ApiService):
    """
    The worker service is the main async task processor in the system. Handles image analysis and image import tasks
    """

    __service_name__ = "analyzer"
    __spec_dir__ = pkg_resources.resource_filename(__name__, "swagger")
    __service_api_version__ = "v1"
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
        "image_analyzer": {
            "handler": handle_image_analyzer,
            "taskType": "handle_image_analyzer",
            "args": [],
            "cycle_timer": 5,
            "min_cycle_timer": 1,
            "max_cycle_timer": 120,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
        "handle_metrics": {
            "handler": handle_metrics,
            "taskType": "handle_metrics",
            "args": [__service_name__],
            "cycle_timer": 15,
            "min_cycle_timer": 15,
            "max_cycle_timer": 15,
            "last_queued": 0,
            "last_return": False,
            "initialized": False,
        },
    }
