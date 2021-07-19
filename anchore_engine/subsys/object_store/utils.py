from anchore_engine.subsys import logger
from anchore_engine.subsys.object_store import ObjectStorageDriver


def _from_config(configuration):
    """
    Return a driver instance from the given configuration. Raises an exception if not found or not valid value in the config.
    Expects to find a driver name in services.catalog.archive_driver, as a string.

    :param configuration:
    :return:
    """
    driver_name = configuration.get("name")
    driver_config = configuration.get("config")

    if not driver_name:
        raise ValueError(
            "Cannot initialize archive driver, no driver name found in configuration"
        )

    drv = ObjectStorageDriver.registry.get(driver_name)
    if not drv:
        raise ValueError(
            "Unknown driver name specified. No driver for name {}".format(driver_name)
        )

    return drv(driver_config)


def init_driver(configuration):
    """
    Returns an initialized driver object constructed from the specified configuration.

    :param configuration:
    :return: ObjectStorageDriver subclassed object
    """

    if not configuration:
        raise ValueError("Cannot initialize an empty configuration")

    try:
        return _from_config(configuration=configuration)
    except Exception as err:
        logger.exception("Error configuring archive driver")
        raise err
