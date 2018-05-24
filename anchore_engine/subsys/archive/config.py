import copy
from anchore_engine.subsys import logger

COMPRESSION_LEVEL = 3

DEFAULT_DRIVER = 'db'

# Config Keys
DEFAULT_MIN_COMPRESSION_LIMIT_KB = 100
MAIN_CONFIG_KEY = 'archive'
COMPRESSION_SECTION_KEY = 'compression'
COMPRESSION_ENABLED_KEY = 'enabled'
COMPRESSION_MIN_SIZE_KEY = 'min_size_kbytes'
DRIVER_SECTION_KEY = 'storage_driver'
DRIVER_NAME_KEY = 'name'
DRIVER_CONFIG_KEY = 'config'
MIGRATION_DRIVER_SECTION_KEY = 'migrate_from_storage_driver'
DEFAULT_COMPRESSION_ENABLED = False

default_config = {
    COMPRESSION_SECTION_KEY: {
        COMPRESSION_ENABLED_KEY: DEFAULT_COMPRESSION_ENABLED,
        COMPRESSION_MIN_SIZE_KEY: DEFAULT_MIN_COMPRESSION_LIMIT_KB,
    },
    DRIVER_SECTION_KEY: {
        DRIVER_NAME_KEY: DEFAULT_DRIVER,
        DRIVER_CONFIG_KEY: {}
    }
}


def normalize_config(service_config):
    """
    Given a top-level catalog service config, validate and return the normalized config (for legacy support)
    :param service_config:
    :return: archive configuration normalized to the current format
    """

    global default_config

    archive_config = service_config.get(MAIN_CONFIG_KEY)

    if not archive_config:
        logger.warn("no '{}' section found in service config, using legacy configuration options".format(MAIN_CONFIG_KEY))
        archive_config = {}
        bkwd = _parse_legacy_config(service_config)
        archive_config.update(bkwd)

    new_conf = copy.deepcopy(default_config)
    if DRIVER_SECTION_KEY in archive_config:
        new_conf[DRIVER_SECTION_KEY].update(archive_config[DRIVER_SECTION_KEY])
    if COMPRESSION_SECTION_KEY in archive_config:
        new_conf[COMPRESSION_SECTION_KEY].update(archive_config[COMPRESSION_SECTION_KEY])

    validate_config(new_conf)
    return new_conf


def validate_config(config):
    """
    Validates either the config exists or is empty and thus defaults. Does not validate specific driver configs as those are up to the drivers themselves.

    :param config:
    :return:
    """
    try:
        if DRIVER_SECTION_KEY in config:
            name = config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY]
            drv_cfg = config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY]
        return True
    except Exception as e:
        raise Exception('Invalid archive driver configuration: {}'.format(e))


def _parse_legacy_config(config):
    """
    Checks a config for older versions of config values. e.g. 'use_db'.

    If no legacy config is found, returns the exact config given.

    :param config: config dict
    :return: parsed archive config values as a dict
    """
    mapped_config = {
        DRIVER_SECTION_KEY: {
            DRIVER_NAME_KEY: None,
            DRIVER_CONFIG_KEY: {}
        }
    }

    if 'archive_driver' in config and type(config['archive_driver']) in [str, str]:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = config['archive_driver']
    else:
        return config

    if 'use_db' in config and config['use_db']:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = 'db'

    if mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] == 'localfs' and 'archive_data_dir' in config:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY]['archive_data_dir'] = config['archive_data_dir']

    if mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] is not None:
        return mapped_config
    else:
        return config
