import os
import re
import sys
import copy
import json
import time
import yaml
import urllib
import logging
import dateutil.parser

from prettytable import PrettyTable, PLAIN_COLUMNS
from collections import OrderedDict
#from textwrap import fill

import anchore_engine.db.entities.common

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

    # error message overrides
    #if op == 'image_add':
    #    if 'httpcode' in errdata and errdata['httpcode'] == 404:
    #        errdata['message'] = "image cannot be found/fetched from registry"

    obuf = ""
    try:
        outdict = OrderedDict()    
        if 'message' in errdata:
            outdict['Error'] = str(errdata['message'])
        if 'httpcode' in errdata:
            outdict['HTTP Code'] = str(errdata['httpcode'])
        if 'detail' in errdata and errdata['detail']:
            outdict['Detail'] = str(errdata['detail'])

        for k in outdict.keys():
            obuf = obuf + k + ": " + outdict[k] + "\n"
        #obuf = obuf + "\n"
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

def connect_database(config, db_connect, db_use_ssl, db_retries=1):
    # allow override of db connect string on CLI, otherwise get DB params from anchore-engine config.yaml
    db_connect_args = {'ssl': False}
    if db_use_ssl:
        db_connect_args['ssl'] = True

    db_params = {
        'db_connect': db_connect,
        'db_connect_args': db_connect_args,
        'db_pool_size': 10,
        'db_pool_max_overflow': 20
    }

    print "DB Params: {}".format(json.dumps(db_params))
    rc = anchore_engine.db.entities.common.do_connect(db_params)
    print "DB connection configured: " + str(rc)

    db_connected = False
    last_db_connect_err = ""
    for i in range(0, int(db_retries)):
        print "Attempting to connect to DB..."
        try:
            rc = anchore_engine.db.entities.common.test_connection()
            print "DB connected: " + str(rc)
            db_connected = True
            break
        except Exception as err:
            last_db_connect_err = str(err)
            if db_retries > 1:
                print "DB connection failed, retrying - exception: " + str(last_db_connect_err)
                time.sleep(5)

    if not db_connected:
        raise Exception("DB connection failed - exception: " + str(last_db_connect_err))
        
def init_database(upgrade_module=None, localconfig=None, do_db_compatibility_check=False):
    code_versions = db_versions = None
    if upgrade_module:
        try:
            if do_db_compatibility_check and "do_db_compatibility_check" in dir(upgrade_module):
                print "DB compatibility check running..."
                upgrade_module.do_db_compatibility_check()
                print "DB compatibility check success"
            else:
                print "DB compatibility check routine not present, skipping..."
        except Exception as err:
            raise err

        try:
            code_versions, db_versions = upgrade_module.get_versions()
            if code_versions and not db_versions:
                print "DB not initialized - initializing tables"
                upgrade_module.do_create_tables()
                upgrade_module.do_db_bootstrap(localconfig=localconfig)
                upgrade_module.do_version_update(db_versions, code_versions)
                code_versions, db_versions = upgrade_module.get_versions()
        except Exception as err:
            raise err

    return(code_versions, db_versions)
