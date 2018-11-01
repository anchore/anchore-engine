import os
import re
import sys
import copy
import json
import time
import yaml
import urllib.request, urllib.parse, urllib.error
import logging
import copy
import dateutil.parser

from prettytable import PrettyTable, PLAIN_COLUMNS
from collections import OrderedDict
#from textwrap import fill

import anchore_engine.db.entities.common
from anchore_engine.subsys import logger

_logger = logging.getLogger(__name__)

def setup_config(cli_opts):
    ret = {
        'jsonmode':False,
        'debug':False,
        'configdir': '/config'
    }

    settings = {}

    # load environment if present
    try:
        for e in ['ANCHORE_CLI_JSON', 'ANCHORE_CLI_DEBUG', 'ANCHORE_CONFIG_DIR']:
            if e in os.environ:
                settings[e] = os.environ[e]
    except Exception as err:
        raise err

    # load cmdline options
    try:
        if cli_opts['json']:
            settings['ANCHORE_CLI_JSON'] = "y"
        
        if cli_opts['debug']:
            settings['ANCHORE_CLI_DEBUG'] = "y"

        if cli_opts['configdir']:
            settings['ANCHORE_CONFIG_DIR'] = cli_opts['configdir']

    except Exception as err:
        raise err

    try:
        if 'ANCHORE_CLI_JSON' in settings:
            if settings['ANCHORE_CLI_JSON'].lower() == 'y':
                ret['jsonmode'] = True
        if 'ANCHORE_CLI_DEBUG' in settings:
            if settings['ANCHORE_CLI_DEBUG'].lower() == 'y':
                ret['debug'] = True
        if 'ANCHORE_CONFIG_DIR' in settings:
            ret['configdir'] = settings['ANCHORE_CONFIG_DIR']
        
    except Exception as err:
        raise err

    return(ret)

def format_error_output(config, op, params, payload):

    try:
        errdata = json.loads(str(payload))
    except:
        errdata = {'message': str(payload)}

    if config['jsonmode']:
        ret = json.dumps(errdata, indent=4, sort_keys=True)
        return(ret)

    obuf = ""
    try:
        outdict = OrderedDict()    
        if 'message' in errdata:
            outdict['Error'] = str(errdata['message'])
        if 'httpcode' in errdata:
            outdict['HTTP Code'] = str(errdata['httpcode'])
        if 'detail' in errdata and errdata['detail']:
            outdict['Detail'] = str(errdata['detail'])

        for k in list(outdict.keys()):
            obuf = obuf + k + ": " + outdict[k] + "\n"

    except Exception as err:
        obuf = str(payload)

    ret = obuf
    return(ret)

def doexit(ecode):
    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
        pass
    sys.exit(ecode)

def make_db_params(db_connect=None, db_use_ssl=False, db_timeout=30, db_connect_timeout=120, db_pool_size=30, db_pool_max_overflow=100):
    db_connect_args = {
        'timeout': db_timeout,
        'ssl': db_use_ssl,
        #'connect_timeout': db_connect_timeout,
    }

    ret = {
        'db_connect': db_connect,
        'db_connect_args': db_connect_args,
        'db_pool_size': db_pool_size,
        'db_pool_max_overflow': db_pool_max_overflow,
    }            
    return(ret)

def connect_database(config, db_params, db_retries=1):
    # db_connect can have secrets - remove them before logging
    loggable_db_params = copy.deepcopy(db_params)
    del loggable_db_params['db_connect']
    logger.info("DB params: {}".format(json.dumps(loggable_db_params)))

    rc = anchore_engine.db.entities.common.do_connect(db_params)
    logger.info("DB connection configured: {}".format(str(rc)))

    db_connected = False
    last_db_connect_err = ""
    for i in range(0, int(db_retries)):
        logger.info("DB attempting to connect...")
        try:
            rc = anchore_engine.db.entities.common.test_connection()
            logger.info("DB connected: {}".format(str(rc)))
            db_connected = True
            break
        except Exception as err:
            last_db_connect_err = str(err)
            if db_retries > 1:
                logger.warn("DB connection failed, retrying - exception: {}".format(str(last_db_connect_err)))
                time.sleep(5)

    if not db_connected:
        raise Exception("DB connection failed - exception: " + str(last_db_connect_err))
        
def init_database(upgrade_module=None, localconfig=None, do_db_compatibility_check=False):
    code_versions = db_versions = None
    if upgrade_module:
        try:
            if do_db_compatibility_check and "do_db_compatibility_check" in dir(upgrade_module):
                logger.info("DB compatibility check: running...")
                upgrade_module.do_db_compatibility_check()
                logger.info("DB compatibility check success")
            else:
                logger.info("DB compatibility check: skipping...")
        except Exception as err:
            raise err

        try:
            code_versions, db_versions = upgrade_module.get_versions()
            if code_versions and not db_versions:
                logger.info("DB not initialized: initializing tables...")
                upgrade_module.do_create_tables()
                upgrade_module.do_db_bootstrap(localconfig=localconfig, db_versions=db_versions, code_versions=code_versions)
                #upgrade_module.do_version_update(db_versions, code_versions)
                code_versions, db_versions = upgrade_module.get_versions()
        except Exception as err:
            raise err

        try:
            if localconfig and "do_db_post_actions" in dir(upgrade_module):
                logger.info("DB post actions: running...")
                upgrade_module.do_db_post_actions(localconfig=localconfig)
        except Exception as err:
            raise err

    return(code_versions, db_versions)
