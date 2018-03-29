import sys
import os
import re
import json
import yaml
import click
import urllib
import importlib

import anchore_engine.db.entities.common
import anchore_engine.subsys.archive
from anchore_engine.subsys import logger

import anchore_manager.cli.utils

config = {}
localconfig = None
module = None

@click.group(name='archivestorage', short_help='Archive Storage operations')
@click.option("--db-connect", nargs=1, required=True, help="DB connection string override.")
@click.option("--db-use-ssl", is_flag=True, help="Set if DB connection is using SSL.")
@click.option("--db-retries", nargs=1, default=1, help="If set, the tool will retry to connect to the DB the specified number of times at 5 second intervals.")
@click.pass_obj
def archivestorage(ctx_config, db_connect, db_use_ssl, db_retries):
    global config, localconfig
    config = ctx_config

    try:
        # do some DB connection/pre-checks here
        try:
            # config and init                                                                                                                                                
            #configfile = configdir = None
            #configdir = config['configdir']
            #configfile = os.path.join(configdir, 'config.yaml')

            #anchore_engine.configuration.localconfig.load_config(configdir=configdir, configfile=configfile)
            #localconfig = anchore_engine.configuration.localconfig.get_config()
            localconfig = {
                'services': {
                    'catalog': {
                        'use_db': True,
                        'archive_driver': 'db',
                        'archive_data_dir': None
                    }
                }
            }

            log_level = 'INFO'
            if config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)

            db_params = anchore_manager.cli.utils.init_database(config, db_connect, db_use_ssl, db_retries=db_retries)
            
            #rc = anchore_engine.db.entities.common.do_connect(db_params)
            #print "DB connected..." + str(rc)

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
@click.option("--archive-data-dir", nargs=1, required=False, help="Location of the archive data directory (needed when converting to/from the localfs driver)")
@click.option("--dontask", is_flag=True, help="Perform conversion (if necessary) without prompting.")
def convert(from_driver, to_driver, archive_data_dir, dontask):
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
            if 'localfs' in [from_driver, to_driver] and not archive_data_dir:
                raise Exception("when converting to/from driver localfs, you must specify --archive-data-dir <path>")

            localconfig['services']['catalog']['archive_driver'] = "{}".format(to_driver)
            localconfig['services']['catalog']['archive_data_dir'] = "{}".format(archive_data_dir)
            if to_driver == 'db':
                localconfig['services']['catalog']['use_db'] = True
            else:
                localconfig['services']['catalog']['use_db'] = False

            # do the conversion
            do_upgrade = False
            if dontask:
                do_upgrade = True
            else:
                try:
                    answer = raw_input("Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)")
                except:
                    answer = "n"
                if 'y' == answer.lower():
                    do_upgrade = True

            if do_upgrade:
                rc = anchore_engine.subsys.archive.initialize(use_driver=to_driver, localconfig=localconfig)
                print "Archive initialized..." + str(rc)

                print "Converting from_driver="+str(from_driver)+" to_driver="+str(to_driver)
                rc = anchore_engine.subsys.archive.do_archive_convert(localconfig, from_driver, to_driver)
                if not rc:
                    raise Exception("archive driver conversion routine returned False")
                print "Done."


                if to_driver == 'db':
                    localconfig['services']['catalog'].pop('archive_data_dir')
                elif to_driver == 'localfs':
                    localconfig['services']['catalog']['use_db'] = False

                print "After this conversion, your anchore-engine config.yaml MUST have the following configuration options added before starting up again:"
                if 'archive_data_dir' in localconfig['services']['catalog']:
                    print "\tNOTE: for archive_data_dir, the value must be set to the location that is accessible within your anchore-engine container"
                print
                print yaml.dump(localconfig, default_flow_style=False)
                print 
            else:
                print "Skipping conversion."
    except Exception as err:
        print anchore_manager.cli.utils.format_error_output(config, 'dbupgrade', {}, err)
        if not ecode:
            ecode = 2

    anchore_manager.cli.utils.doexit(ecode)

