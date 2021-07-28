import copy
from anchore_engine.subsys import logger

COMPRESSION_LEVEL = 3

DEFAULT_DRIVER = "db"
DEFAULT_OBJECT_STORE_MANAGER_ID = "object_store"
ALT_OBJECT_STORE_CONFIG_KEY = "archive"

DEFAULT_MIN_COMPRESSION_LIMIT_KB = 100
ANALYSIS_ARCHIVE_MANAGER_ID = "analysis_archive"

COMPRESSION_SECTION_KEY = "compression"
COMPRESSION_ENABLED_KEY = "enabled"
COMPRESSION_MIN_SIZE_KEY = "min_size_kbytes"
DRIVER_SECTION_KEY = "storage_driver"
DRIVER_NAME_KEY = "name"
DRIVER_CONFIG_KEY = "config"
MIGRATION_DRIVER_SECTION_KEY = "migrate_from_storage_driver"
DEFAULT_COMPRESSION_ENABLED = False

default_config = {
    COMPRESSION_SECTION_KEY: {
        COMPRESSION_ENABLED_KEY: DEFAULT_COMPRESSION_ENABLED,
        COMPRESSION_MIN_SIZE_KEY: DEFAULT_MIN_COMPRESSION_LIMIT_KB,
    },
    DRIVER_SECTION_KEY: {DRIVER_NAME_KEY: DEFAULT_DRIVER, DRIVER_CONFIG_KEY: {}},
}


def extract_config(service_config, config_keys):
    """
    Extract the exact config from the config dict, may be None if none is found in any of the config_keys items

    :param service_config: the config dict to extract from
    :param config_keys: tuple/list of dict keys to use in order of precedence
    :return: the configuration dict if found, or None
    """

    for key in config_keys:
        config_key = key
        obj_store_config = service_config.get(config_key)
        if obj_store_config:
            return obj_store_config
    else:
        return None


def normalize_config(obj_store_config, legacy_fallback=False, service_config=None):
    """
    Given a top-level catalog service config, validate and return the normalized config (for legacy support)

    :param obj_store_config: the extracted object store configuration
    :param legacy_fallback: boolean, if set and no config found in obj_store_config, try to create one from the service_config
    :param service_config: optional full service config if legacy_fallback is enabled.
    :return:
    """

    global default_config

    # obj_store_config = extract_config(service_config, config_keys)

    if legacy_fallback and not obj_store_config:
        logger.warn(
            "no current object storage configuration found in service config, using legacy configuration options"
        )
        obj_store_config = {}
        bkwd = _parse_legacy_config(service_config)
        obj_store_config.update(bkwd)

    new_conf = copy.deepcopy(default_config)
    if DRIVER_SECTION_KEY in obj_store_config:
        new_conf[DRIVER_SECTION_KEY].update(obj_store_config[DRIVER_SECTION_KEY])
    if COMPRESSION_SECTION_KEY in obj_store_config:
        new_conf[COMPRESSION_SECTION_KEY].update(
            obj_store_config[COMPRESSION_SECTION_KEY]
        )

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
        raise Exception("Invalid archive driver configuration: {}".format(e))


def _parse_legacy_config(config):
    """
    Checks a config for older versions of config values. e.g. 'use_db'.

    If no legacy config is found, returns the exact config given.

    :param config: config dict
    :return: parsed archive config values as a dict
    """
    mapped_config = {DRIVER_SECTION_KEY: {DRIVER_NAME_KEY: None, DRIVER_CONFIG_KEY: {}}}

    if "archive_driver" in config and type(config["archive_driver"]) in [str, str]:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = config["archive_driver"]
    else:
        return config

    if "use_db" in config and config["use_db"]:
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] = "db"

    if (
        mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] == "localfs"
        and "archive_data_dir" in config
    ):
        mapped_config[DRIVER_SECTION_KEY][DRIVER_CONFIG_KEY][
            "archive_data_dir"
        ] = config["archive_data_dir"]

    if mapped_config[DRIVER_SECTION_KEY][DRIVER_NAME_KEY] is not None:
        return mapped_config
    else:
        return config
