import inspect
import logging
import sys
import threading

from pythonjsonlogger import jsonlogger
from twisted.python import log

from anchore_engine.db.entities.common import anchore_now_datetime

bootstrap_logger = None
bootstrap_logger_enabled = False

DEFAULT_TESTLOG_FORMAT = "[{}] %(asctime)s [-] [%(name)s] [%(levelname)s] %(message)s"
DEFAULT_FORMAT = "%(asctime)s [-] [%(name)s] [%(levelname)s] %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S+0000"

DEFAULT_LOGGERS = [logging.getLogger(), logging.getLogger("twisted")]

SUPPRESSED_LIBRARY_LOGGERS = ["yosai.core.mgt.mgt", "yosai.core.event.event"]


def enable_test_logging(level="WARN", outfile=None):
    """
    Use the bootstrap logger for logging in test code (as root logger), for
    intercept by pytest etc. This code should *only* ever be called in code
    from test/

    :return:
    """
    prefix = "test"
    if outfile:
        logging.basicConfig(
            level=level,
            filename=outfile,
            format=DEFAULT_TESTLOG_FORMAT.format(prefix),
            datefmt=DEFAULT_DATE_FORMAT,
        )
    else:
        logging.basicConfig(
            level=level,
            stream=sys.stdout,
            format=DEFAULT_TESTLOG_FORMAT.format(prefix),
            datefmt=DEFAULT_DATE_FORMAT,
        )


def configure_logging(new_log_level, json_logging_enabled=False):
    """
    Setup standard lib logging, and route twisted logs to the standard library
    :param new_log_level: a string name of log level, e.g. 'INFO', 'DEBUG'
    :param json_logging_enabled: whether to enable json logging or not
    :return:
    """
    logging.basicConfig(level=new_log_level, force=True)
    for logger in DEFAULT_LOGGERS:
        if json_logging_enabled:
            formatter = AnchoreJsonLogFormatter()
        else:
            formatter = logging.Formatter(DEFAULT_FORMAT)
            formatter.datefmt = DEFAULT_DATE_FORMAT

        setup_log_handler(new_log_level, logger, formatter)

    # This should allow Twisted to leverage python standard library logging configuration
    observer = log.PythonLoggingObserver()
    observer.start()

    # Some libraries spew out lots of warning logs in normal application execution, so we'll suppress them here
    for logger_name in SUPPRESSED_LIBRARY_LOGGERS:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.CRITICAL)

    logging.getLogger().info("Logging Configuration complete")


def setup_log_handler(level, logger, formatter):

    logger.handlers = []
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(formatter)
    log_handler.setLevel(level)
    logger.addHandler(log_handler)


class AnchoreJsonLogFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(AnchoreJsonLogFormatter, self).add_fields(
            log_record, record, message_dict
        )
        if not log_record.get("timestamp"):
            # this doesn't use record.created, so it is slightly off
            now = anchore_now_datetime().strftime(DEFAULT_DATE_FORMAT)
            log_record["timestamp"] = now

        if log_record.get("level"):
            log_record["level"] = log_record["level"].upper()
        else:
            log_record["level"] = record.levelname

        thread_name, caller_file, caller_name = self.get_anchore_log_data()
        anchore_data = {"thread": thread_name, "file": caller_file, "name": caller_name}
        log_record["anchore_data"] = anchore_data

    @staticmethod
    def get_anchore_log_data():
        tname = threading.current_thread().getName()
        caller_file = "-"
        caller_name = "-"
        try:
            current_frame = inspect.currentframe()
            outer_frame = inspect.getouterframes(current_frame, 3)
            frame = inspect.stack()[3]
            module = inspect.getmodule(frame[0])
            caller_file = module.__name__
            caller_name = outer_frame[3][3]
        except Exception:
            pass

        return tname, caller_file, caller_name
