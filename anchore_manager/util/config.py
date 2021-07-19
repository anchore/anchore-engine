import copy
import os

from . import logging

DEFAULT_CONFIG = {"jsonmode": False, "debug": False, "configdir": "/config"}


def setup_config(cli_opts):
    """
    Initialize the config from the default
    :param cli_opts:
    :return:
    """
    ret = copy.copy(DEFAULT_CONFIG)

    settings = {}

    # load environment if present
    for e in ["ANCHORE_CLI_JSON", "ANCHORE_CLI_DEBUG", "ANCHORE_CONFIG_DIR"]:
        if e in os.environ:
            settings[e] = os.environ[e]

    # load cmdline options

    if cli_opts["json"]:
        settings["ANCHORE_CLI_JSON"] = "y"

    if cli_opts["debug"]:
        settings["ANCHORE_CLI_DEBUG"] = "y"

    if cli_opts["configdir"]:
        settings["ANCHORE_CONFIG_DIR"] = cli_opts["configdir"]

    if settings.get("ANCHORE_CLI_JSON", "").lower() == "y":
        ret["jsonmode"] = True
    if settings.get("ANCHORE_CLI_DEBUG", "").lower() == "y":
        ret["debug"] = True
    if "ANCHORE_CONFIG_DIR" in settings:
        ret["configdir"] = settings["ANCHORE_CONFIG_DIR"]

    return ret


def init_all(cli_opts):
    conf = setup_config(cli_opts)
    logging.log_config(conf)
    return conf
