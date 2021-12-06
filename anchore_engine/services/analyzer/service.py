import os
import time

import pkg_resources

import anchore_engine.subsys
from anchore_engine.common.models.schemas import QueueMessage
from anchore_engine.configuration import localconfig
from anchore_engine.service import ApiService
from anchore_engine.services.analyzer.watchers.analysis import AnalysisWatcher
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
        AnalysisWatcher.config.watcher_key: AnalysisWatcher().to_watcher_dict(),
    }
