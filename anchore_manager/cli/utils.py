import os
import re
import sys
import copy
import json
import yaml
import urllib
import logging
import dateutil.parser

from prettytable import PrettyTable, PLAIN_COLUMNS
from collections import OrderedDict
#from textwrap import fill

import anchorecli.clients.apiexternal

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

