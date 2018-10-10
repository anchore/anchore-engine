import sys
import os
import json
import click
import importlib
import time

import anchore_engine.db.entities.common
from anchore_engine.db.entities.exceptions import TableNotFoundError
from anchore_engine.db.entities.exceptions import is_table_not_found
from anchore_engine.subsys import logger

import anchore_manager.cli.utils

config = {}
module = None

@click.group(name='db', short_help='DB operations')
@click.pass_obj
@click.option("--db-connect", nargs=1, required=True, help="DB connection string override.")
@click.option("--db-use-ssl", is_flag=True, help="Set if DB connection is using SSL.")
@click.option("--db-retries", nargs=1, default=1, type=int, help="If set, the tool will retry to connect to the DB the specified number of times at 5 second intervals.")
@click.option("--db-timeout", nargs=1, default=86400, type=int, help="Number of seconds to wait for DB call to complete before timing out.")
@click.option("--db-connect-timeout", nargs=1, default=120, type=int, help="Number of seconds to wait for initial DB connection before timing out.")
def db(ctx_config, db_connect, db_use_ssl, db_retries, db_timeout, db_connect_timeout):
    global config, module
    config = ctx_config

    try:
        # do some DB connection/pre-checks here
        try:

            log_level = 'INFO'
            if config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)

            db_params = anchore_manager.cli.utils.make_db_params(db_connect=db_connect, db_use_ssl=db_use_ssl, db_timeout=db_timeout, db_connect_timeout=db_connect_timeout)
            db_params = anchore_manager.cli.utils.connect_database(config, db_params, db_retries=db_retries)

        except Exception as err:
            raise err

    except Exception as err:
        logger.error(anchore_manager.cli.utils.format_error_output(config, 'db', {}, err))
        sys.exit(2)


@db.command(name='upgrade', short_help="Upgrade DB to version compatible with installed anchore-engine code.")
@click.option("--anchore-module", nargs=1, help="Name of anchore module to call DB upgrade routines from (default=anchore_engine)")
@click.option("--dontask", is_flag=True, help="Perform upgrade (if necessary) without prompting.")
@click.option("--skip-db-compat-check", is_flag=True, help="Skip the database compatibility check.")
def upgrade(anchore_module, dontask, skip_db_compat_check):

    """
    Run a Database Upgrade idempotently. If database is not initialized yet, but can be connected, then exit cleanly with status = 0, if no connection available then return error.
    Otherwise, upgrade from the db running version to the code version and exit.

    """
    ecode = 0

    if not anchore_module:
        module_name = "anchore_engine"
    else:
        module_name = str(anchore_module)

    try:
        try:
            logger.info("Loading DB upgrade routines from module.")
            module = importlib.import_module(module_name + ".db.entities.upgrade")
        except Exception as err:
            raise Exception("Input anchore-module (" + str(module_name) + ") cannot be found/imported - exception: " + str(err))

        code_versions, db_versions = anchore_manager.cli.utils.init_database(upgrade_module=module, do_db_compatibility_check=(not skip_db_compat_check))

        code_db_version = code_versions.get('db_version', None)
        running_db_version = db_versions.get('db_version', None)

        if not code_db_version or not running_db_version:
            raise Exception("cannot get version information (code_db_version={} running_db_version={})".format(code_db_version, running_db_version))
        elif code_db_version == running_db_version:
            logger.info("Code and DB versions are in sync.")
            ecode = 0
        else:
            logger.info("Detected anchore-engine version {}, running DB version {}.".format(code_db_version, running_db_version))

            do_upgrade = False
            if dontask:
                do_upgrade = True
            else:
                try:
                    answer = input("Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)")
                except:
                    answer = "n"
                if 'y' == answer.lower():
                    do_upgrade = True

            if do_upgrade:
                logger.info("Performing upgrade.")
                try:
                    # perform the upgrade logic here
                    rc = module.run_upgrade()
                    if rc:
                        logger.info("Upgrade completed")
                    else:
                        logger.info("No upgrade necessary. Completed.")
                except Exception as err:
                    raise err
            else:
                logger.info("Skipping upgrade.")
    except Exception as err:
        logger.error(anchore_manager.cli.utils.format_error_output(config, 'dbupgrade', {}, err))
        if not ecode:
            ecode = 2

    anchore_manager.cli.utils.doexit(ecode)
