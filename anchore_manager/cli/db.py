import sys
import os
import re
import json
import click
import urllib
import importlib

import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

import anchore_engine.configuration.localconfig
import anchore_engine.db.entities.common
from anchore_engine.subsys import logger

import anchore_manager.cli.utils

config = {}
module = None

@click.group(name='db', short_help='DB operations')
@click.pass_obj
def db(ctx_config):
    global config, module
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
        print anchore_manager.cli.utils.format_error_output(config, 'db', {}, err)
        sys.exit(2)

@db.command(name='upgrade', short_help="Upgrade DB to version compatible with installed anchore-engine code.")
@click.option("--anchore-module", nargs=1, help="Name of anchore module to call DB upgrade routines from (default=anchore_engine)")
def upgrade(anchore_module):
    """
    """
    ecode = 0

    if not anchore_module:
        module_name = "anchore_engine"
    else:
        module_name = str(anchore_module)

    try:
        try:
            print "Loading DB upgrade routines from module."
            module = importlib.import_module(module_name + ".db.entities.upgrade")
            code_versions, db_versions = module.get_versions()
        except Exception as err:
            raise Exception("Input anchore-module ("+str(module_name)+") cannot be found/imported - exception: " + str(err))

        code_db_version = code_versions.get('db_version', None)
        running_db_version = db_versions.get('db_version', None)

        if not code_db_version or not running_db_version:
            raise Exception("cannot gather either code or running DB version (code_db_version={} running_db_version={})".format(code_db_version, running_db_version))
        elif code_db_version == running_db_version:
            print "Detected anchore-engine version {} and running DB version {} match, nothing to do.".format(code_db_version, running_db_version)
        else:
            print "Detected anchore-engine version {}, running DB version {}.".format(code_db_version, running_db_version)

            do_upgrade = False
            try:
                answer = raw_input("Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)")
            except:
                answer = "n"
            if 'y' == answer.lower():
                do_upgrade = True

            if do_upgrade:
                print "Performing upgrade."
                try:
                    # perform the upgrade logic here
                    rc = module.do_upgrade(db_versions, code_versions)
                    if rc:
                        # if successful upgrade, set the DB values to the incode values
                        rc = module.do_upgrade_success(db_versions, code_versions)
                        print "Upgrade success: " + str(rc)
                    else:
                        raise Exception("Upgrade routine from module returned false, please check your DB/environment and try again")

                    print "Done."
                except Exception as err:
                    raise err
            else:
                print "Skipping upgrade."
    except Exception as err:
        print anchore_manager.cli.utils.format_error_output(config, 'dbupgrade', {}, err)
        if not ecode:
            ecode = 2

    anchore_manager.cli.utils.doexit(ecode)

