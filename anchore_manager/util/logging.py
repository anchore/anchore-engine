import json
import logging
import sys
from collections import OrderedDict

from anchore_engine.subsys import logger
from anchore_manager.util.config import DEFAULT_CONFIG
from anchore_manager.util.proc import ExitCode

# Sane default
_log_config = DEFAULT_CONFIG


def format_error_output(config, op, params, payload):
    """
    Format output for CLI use based on config  options

    :param config: cli configuration
    :param op: operation name string
    :param params: params to the operation
    :param payload: error to format
    :return:
    """

    try:
        errdata = json.loads(str(payload))
    except:
        errdata = {"message": str(payload)}

    if config["jsonmode"]:
        return json.dumps(errdata, indent=4, sort_keys=True)

    obuf = ""
    try:
        outdict = OrderedDict()
        if "message" in errdata:
            outdict["Error"] = str(errdata["message"])
        if "httpcode" in errdata:
            outdict["HTTP Code"] = str(errdata["httpcode"])
        if "detail" in errdata and errdata["detail"]:
            outdict["Detail"] = str(errdata["detail"])

        for k in list(outdict.keys()):
            obuf = obuf + k + ": " + outdict[k] + "\n"

    except Exception as err:
        obuf = str(payload)

    return obuf


def log_config(config: dict):
    """
    Initialize some logging for the cli ops

    :param config:
    :return:
    """
    global _log_config

    if config["debug"]:
        logging.basicConfig(level=logging.DEBUG)

    _log_config.update(config)

    try:
        log_level = "INFO"
        if config["debug"]:
            log_level = "DEBUG"

        logger.set_log_level(log_level, log_to_stdout=True)

    except Exception as err:
        logger.error(format_error_output(config, "service", {}, err))

        sys.exit(ExitCode.failed.value)


def log_error(message: str, err: Exception):
    """
    Log a CLI-formatted error based on the config initialized in a previous log_config() call

    :param message:
    :param err:
    :return:
    """
    global _log_config
    logger.error(format_error_output(_log_config, "dbupgrade", {}, err))
