import os
import re
import json
import uuid
import time
import yaml
import shutil

from pkg_resources import resource_filename

from anchore_engine.subsys import logger

DEFAULT_CONFIG = {
    'service_dir': '/root/.anchore_engine',
    'tmp_dir': '/tmp',
    'log_level': 'INFO',
    'metrics': {'enable': False},
    'image_analyze_timeout_seconds': '36000',
    'cleanup_images': False,
    'internal_ssl_verify': True,
    'auto_restart_services': True,
    'services': {},
    'credentials': {},
    'webhooks': {},
    'default_bundle_file': None,
    'docker_conn': 'unix://var/run/docker.sock',
    'docker_conn_timeout': 600,
    'allow_awsecr_iam_auto': False,
    'skopeo_global_timeout': 0,
    'feeds': {
        'anonymous_user_username': 'anon@ancho.re',
        'anonymous_user_password': 'pbiU2RYZ2XrmYQ',
        'url': 'https://ancho.re/v1/service/feeds',
        'client_url': 'https://ancho.re/v1/account/users',
        'token_url': 'https://ancho.re/oauth/token',
        'connection_timeout_seconds': 3,
        'read_timeout_seconds': 60,
        'selective_sync': {
            'enabled': True,
            'feeds': {
                'vulnerabilities': True,
                'packages': True,
                'nvd': True,
                'snyk': True
            }
        }
    }
}

DEFAULT_CONFIG_FILENAME = 'config.yaml'
localconfig = {}

# System configuration for identities and bootstrap
SYSTEM_ACCOUNT_NAME = 'anchore-system'
SYSTEM_USERNAME = 'anchore-system'
ADMIN_ACCOUNT_NAME = 'admin'
ADMIN_USERNAME = 'admin'
ADMIN_USER_DEFAULT_PASSWORD = 'foobar' # This is used if the config doesn't include a value for the key referenced by DEFAULT_ADMIN_PASSWORD_KEY
DEFAULT_ADMIN_PASSWORD_KEY = 'default_admin_password'
DEFAULT_ADMIN_EMAIL_KEY = 'default_admin_email'
GLOBAL_RESOURCE_DOMAIN = 'system' # Used as the domain for things like accounts

RESERVED_ACCOUNT_NAMES = [
    GLOBAL_RESOURCE_DOMAIN,
    SYSTEM_ACCOUNT_NAME,
    ADMIN_ACCOUNT_NAME
]

PROTECTED_ACCOUNT_NAMES = [
    GLOBAL_RESOURCE_DOMAIN,
    SYSTEM_ACCOUNT_NAME
]

PROTECTED_USER_NAMES = [
    SYSTEM_USERNAME,
    ADMIN_USERNAME
]

# Top-level config keys required to be present
default_required_config_params = {'services': True, 'webhooks': True, 'credentials': True}


def update_merge(base, override):
    if not isinstance(base, dict) or not isinstance(override, dict):
        return

    for k, v in override.items():
        if k in base and type(base[k]) != type(v):
            base[k] = v
        else:
            if k in base and isinstance(base[k], dict):
                update_merge(base[k], v)
            else:
                base[k] = v
    return

def get_host_id():
    global localconfig

    ret = None

    if 'host_id' in localconfig:
        ret = localconfig['host_id']
    else:
        idfile = os.path.join(localconfig['service_dir'], 'host_id.json')
        if not os.path.exists(idfile):
            ret = str(uuid.uuid4())
            with open(idfile, 'w') as OFH:
                OFH.write(json.dumps({'host_id': ret}))
        else:
            for i in range(0,5):
                try:
                    with open(idfile, 'r') as FH:
                        data = json.loads(FH.read())
                        ret = data['host_id']
                    break
                except Exception as err:
                    time.sleep(1)
                    pass

    return (ret)


def load_defaults(configdir=None):
    global localconfig, DEFAULT_CONFIG

    if not configdir:
        try:
            configdir = os.path.join(os.environ['HOME'], ".anchore_engine")
        except:
            configdir = "/root/.anchore_engine"

    localconfig.update(DEFAULT_CONFIG)
    localconfig['service_dir'] = configdir

    return (localconfig)


def load_config(configdir=None, configfile=None, validate_params=None):
    global localconfig

    load_defaults(configdir=configdir)

    if not configfile:
        configfile = os.path.join(localconfig['service_dir'], DEFAULT_CONFIG_FILENAME)

    if not os.path.exists(configfile):
        raise Exception("config file (" + str(configfile) + ") not found")
    else:
        try:
            confdata = read_config(configfile=configfile, validate_params=validate_params)
            update_merge(localconfig, confdata)
        except Exception as err:
            raise err

    # setup service dir
    if not os.path.exists(os.path.join(localconfig['service_dir'])):
        success = False
        for i in range(0,5):
            try:
                os.makedirs(os.path.join(localconfig['service_dir']))
                success = True
            except:
                time.sleep(1)
        if not success:
            raise Exception("could not create service directory: " + str(localconfig['service_dir']))

    # setup tmp dir
    if not os.path.exists(os.path.join(localconfig['tmp_dir'])):
        success = False
        for i in range(0,5):
            try:
                os.makedirs(os.path.join(localconfig['tmp_dir']))
                success = True
            except:
                time.sleep(1)
        if not success:
            raise Exception("could not create temporary directory: " + str(localconfig['tmp_dir']))
        
    # copy the src installed files unless they already exist in the service dir conf
    for key, fname in [('default_bundle_file', 'anchore_default_bundle.json'),
                       ('anchore_scanner_analyzer_config_file', 'analyzer_config.yaml')]:
        try:
            default_file = os.path.join(localconfig['service_dir'], fname)
            localconfig[key] = default_file
            if not os.path.exists(default_file):
                src_file = os.path.join(resource_filename("anchore_engine", "conf/"), fname)
                if os.path.exists(src_file):
                    shutil.copy(src_file, default_file)
        except:
            localconfig[key] = None

    # generate/setup the host_id in the service_dir
    localconfig['host_id'] = get_host_id()

    # any special overrides/deprecation handling here
    try:
        analyzer_config = localconfig.get('services', {}).get('analyzer', {})
        if analyzer_config and analyzer_config.get('analyzer_driver', 'localanchore') != 'nodocker':
            if not os.path.exists("/usr/bin/anchore"):
                logger.warn("the 'localanchore' analyzer driver has been removed from anchore-engine - defaulting to 'nodocker' analyzer driver")
                localconfig['services']['analyzer']['analyzer_driver'] = 'nodocker'
    except Exception as err:
        logger.warn(str(err))
        pass

    return (localconfig)


def read_config(configfile=None, validate_params=None):
    ret = {}

    if not configfile or not os.path.exists(configfile):
        raise Exception("no config file (" + str(configfile) + ") can be found to load")
    else:
        try:
            with open(configfile, 'r') as FH:
                confbuf = FH.read()
        except Exception as err:
            raise err

        try:
            anchore_envs = {}
            if 'ANCHORE_ENV_FILE' in os.environ and os.path.exists(os.environ['ANCHORE_ENV_FILE']):
                try:
                    with open(os.environ['ANCHORE_ENV_FILE'], 'r') as FH:
                        secret_envbuf = FH.read()
                    for line in secret_envbuf.splitlines():
                        try:
                            (k, v) = line.split("=", 1)
                            v = re.sub("^(\"|')+", "", v)
                            v = re.sub("(\"|')+$", "", v)
                            if re.match("^ANCHORE.*", k):
                                anchore_envs[k] = str(v)
                        except Exception as err:
                            logger.warn("cannot parse line from ANCHORE_ENV_FILE - exception: " + str(err))
                except Exception as err:
                    raise err

            for e in list(os.environ.keys()):
                if re.match("^ANCHORE.*", e):
                    anchore_envs[e] = str(os.environ[e])

            if anchore_envs:
                confbufcopy = confbuf
                try:
                    for e in list(anchore_envs.keys()):
                        confbufcopy = confbufcopy.replace("${"+str(e)+"}", anchore_envs[e])
                except Exception as err:
                    logger.warn("problem replacing configuration variable values with overrides - exception: " + str(err))
                else:
                    confbuf = confbufcopy

            confdata = yaml.load(confbuf)
            if confdata:
                ret.update(confdata)
        except Exception as err:
            raise err

    try:
        validate_config(ret, validate_params=validate_params)
    except Exception as err:
        raise Exception("invalid configuration: details - " + str(err))

    return (ret)


def validate_config(config, validate_params=None):
    """
    Validate the configuration with required keys and values

    :param config: the config dict to validate
    :param validate_params: dict of top level config properties and boolean flag
    :return: true if passes validation, false otherwise
    """
    ret = True

    if validate_params is None:
        validate_params = default_required_config_params

    try:
        # ensure there aren't any left over unset variables
        confbuf = json.dumps(config)
        patt = re.match(".*(\${ANCHORE.*?}).*", confbuf, re.DOTALL)
        if patt:
            raise Exception("variable overrides found in configuration file that are unset ("+str(patt.group(1))+")")

        # top level checks
        if 'services' in validate_params and validate_params['services']:
            if'services' not in config or not config['services']:
                raise Exception("no 'services' definition in configuration file")
            else:
                for k in list(config['services'].keys()):
                    if not config['services'][k] or 'enabled' not in config['services'][k]:
                        raise Exception("service (" + str(
                            k) + ") defined, but no values are specified (need at least 'enabled: <True|False>')")
                    else:
                        service_config = config['services'][k]

                        # check to ensure the listen/port/endpoint_hostname params are set for all services
                        check_keys = ['endpoint_hostname', 'listen', 'port']
                        for check_key in check_keys:
                            if check_key not in service_config:
                                raise Exception("the following values '{}' must be set for all services, but service '{}' does not have them set (missing '{}')".format(check_keys, k, check_key))

                        # check to ensure that if any TLS params are set, then they all must be set
                        found_key = 0
                        check_keys = ['ssl_enable', 'ssl_cert', 'ssl_key']
                        for check_key in check_keys:
                            if check_key in service_config:
                                found_key = found_key + 1
                        if found_key != 0 and found_key != 3:
                            raise Exception("if any one of (" + ','.join(
                                check_keys) + ") are specified, then all must be specified for service '" + str(k) + "'")

        if 'credentials' in validate_params and validate_params['credentials']:
            if 'credentials' not in config or not config['credentials']:
                raise Exception("no 'credentials' definition in configuration file")
            else:
                credentials = config['credentials']
                for check_key in ['database']:
                    if check_key not in credentials:
                        raise Exception(
                            "no '" + str(check_key) + "' definition in 'credentials' section of configuration file")
                    elif not credentials[check_key]:
                        raise Exception("'"+str(check_key) + "' is in configuration file, but is empty (has no records)")

                # database checks
                for check_key in ['db_connect', 'db_connect_args']:
                    if check_key not in credentials['database']:
                        raise Exception("no '" + str(
                            check_key) + "' definition in 'credentials'/'database' section of configuration file")

            # webhook checks
            if 'webhooks' in validate_params and validate_params['webhooks']:
                if 'webhooks' not in config or not config['webhooks']:
                    logger.warn("no webhooks defined in configuration file - notifications will be disabled")

    except Exception as err:
        logger.error(str(err))
        raise err

    # raise Exception("TEST")
    return (ret)


def get_config():
    global localconfig
    return (localconfig)


def get_versions():
    from anchore_engine import version

    ret = {}
    ret['service_version'] = version.version
    ret['db_version'] = version.db_version

    return (ret)
