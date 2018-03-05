import sys
import os
import re
import json
import click
import urllib
import importlib

import anchore_engine.configuration.localconfig
import anchore_engine.db.entities.common
import anchore_engine.subsys.archive
from anchore_engine.subsys import logger

import anchore_manager.cli.utils

config = {}
localconfig = None
module = None

@click.group(name='archivestorage', short_help='Archive Storage operations')
@click.pass_obj
def archivestorage(ctx_config):
    global config, localconfig
    config = ctx_config

    try:
        # do some DB connection/pre-checks here
        try:
            # config and init                                                                                                                                                
            configfile = configdir = None
            configdir = config['configdir']
            configfile = os.path.join(configdir, 'config.yaml')

            anchore_engine.configuration.localconfig.load_config(configdir=configdir, configfile=configfile)
            localconfig = anchore_engine.configuration.localconfig.get_config()

            log_level = 'INFO'
            if config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)

            db_params = anchore_engine.db.entities.common.get_params(localconfig)
            rc = anchore_engine.db.entities.common.do_connect(db_params)
            print "DB connected..." + str(rc)

        except Exception as err:
            raise err

    except Exception as err:
        print anchore_manager.cli.utils.format_error_output(config, 'archivestorage', {}, err)
        sys.exit(2)

@archivestorage.command(name="list-drivers", short_help="Show a list of available drivers that can be a source or destination for conversion.")
def list_drivers():
    """
    """
    ecode = 0

    try:
        drivers = anchore_engine.subsys.archive.get_driver_list()
        print "Supported convertable drivers: " +str(drivers)
    except Exception as err:
        print anchore_manager.cli.utils.format_error_output(config, 'dbupgrade', {}, err)
        if not ecode:
            ecode = 2

    anchore_manager.cli.utils.doexit(ecode)

@archivestorage.command(name='convert', short_help="Convert between archive storage driver formats.")
@click.option("--from-driver", nargs=1, required=True, help="Name of the currently installed archive storage driver from an extant anchore-engine deployment.")
@click.option("--to-driver", nargs=1, required=True, help="Name of the driver to convert archive storage documents into.")
def convert(from_driver, to_driver):
    global localconfig

    """
    """
    ecode = 0

    try:
        drivers = anchore_engine.subsys.archive.get_driver_list()
        if from_driver not in drivers or to_driver not in drivers:
            raise Exception("both from_driver and to_driver must be in the list of supported convertable drivers: " + str(drivers))
        elif from_driver == to_driver:
            print "from_driver and to_driver are the same, nothing to do"
        else:
            # do the conversion
            rc = anchore_engine.subsys.archive.initialize(use_driver=to_driver)
            print "Archive initialized..." + str(rc)

            print "Converting from_driver="+str(from_driver)+" to_driver="+str(to_driver)
            rc = anchore_engine.subsys.archive.do_archive_convert(localconfig, from_driver, to_driver)
            if not rc:
                raise Exception("archive driver conversion routine returned False")
            print "Done."
    except Exception as err:
        print anchore_manager.cli.utils.format_error_output(config, 'dbupgrade', {}, err)
        if not ecode:
            ecode = 2

    anchore_manager.cli.utils.doexit(ecode)

