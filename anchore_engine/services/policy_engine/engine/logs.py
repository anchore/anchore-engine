import logging
from anchore_engine.subsys import logger as twistd_logging

# Flag used for controlling log behavior to facilitate testing outside of the twistd execution environment
test_mode = False


class LoggingWrapper(object):
    """
    A simple wrapper to approximate a standard logger object that passes thru to the twistd logger
    """

    def info(self, *args, **kwargs):
        twistd_logging.info(*args, **kwargs)

    def exception(self, *args, **kwargs):
        twistd_logging.exception(*args, **kwargs)

    def debug(self, *args, **kwargs):
        twistd_logging.debug(*args, **kwargs)

    def warn(self, *args, **kwargs):
        twistd_logging.warn(*args, **kwargs)

    def error(self, *args, **kwargs):
        twistd_logging.error(*args, **kwargs)

    def spew(self, *args, **kwargs):
        twistd_logging.spew(*args, **kwargs)


def get_logger():
    """
    Logging factory function to allow use of standard logger for things like unit tests or execution outside of the twistd framework
    :return:
    """
    global test_mode
    if test_mode:
        return logging.getLogger()
    else:
        return LoggingWrapper()
