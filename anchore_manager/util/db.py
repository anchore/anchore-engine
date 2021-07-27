"""
Utilities for the manager cli's db operations
"""
import copy
import importlib
import json
import time

import anchore_engine.db
from anchore_engine.db.entities.common import normalize_db_params
from anchore_engine.subsys import logger

ENGINE_UPGRADE_MODULE_NAME = "anchore_engine.db.entities.upgrade"

_db_context = {"params": {}, "retries": 3}


def init_db_context(db_connect, db_use_ssl, db_timeout, db_connect_timeout, db_retries):
    """
    Initialize the db context

    :param config:
    :param db_connect:
    :param db_use_ssl:
    :param db_timeout:
    :param db_connect_timeout:
    :param db_retries:
    :return:
    """
    global _db_context

    # do some DB connection/pre-checks here
    _db_context["params"].update(
        make_db_params(
            db_connect=db_connect,
            db_use_ssl=db_use_ssl,
            db_timeout=db_timeout,
            db_connect_timeout=db_connect_timeout,
        )
    )
    _db_context["retries"] = db_retries
    return _db_context


def db_context():
    return _db_context


def make_db_params(
    db_connect=None,
    db_use_ssl=False,
    db_timeout=30,
    db_connect_timeout=120,
    db_pool_size=30,
    db_pool_max_overflow=100,
):
    db_connect_args = {
        "timeout": db_timeout,
        "ssl": db_use_ssl,
    }

    db_params = {
        "db_connect": db_connect,
        "db_connect_args": db_connect_args,
        "db_pool_size": db_pool_size,
        "db_pool_max_overflow": db_pool_max_overflow,
    }

    return normalize_db_params(db_params)


def connect_database(db_params, db_retries=1):
    # db_connect can have secrets - remove them before logging
    loggable_db_params = copy.deepcopy(db_params)
    del loggable_db_params["db_connect"]
    logger.info("DB params: %s", json.dumps(loggable_db_params))

    rc = anchore_engine.db.entities.common.do_connect(db_params)
    logger.info("DB connection configured: %s", str(rc))

    db_connected = False
    last_db_connect_err = ""
    for i in range(0, int(db_retries)):
        logger.info("DB attempting to connect...")
        try:
            rc = anchore_engine.db.entities.common.test_connection()
            logger.info("DB connected: %s", str(rc))
            db_connected = True
            break
        except Exception as err:
            last_db_connect_err = str(err)
            if db_retries > 1:
                logger.warn(
                    "DB connection failed, retrying - exception: %s",
                    str(last_db_connect_err),
                )
                time.sleep(5)

    if not db_connected:
        raise Exception(
            "DB connection failed - exception: %s" + str(last_db_connect_err)
        )


def init_database(
    upgrade_module=None, localconfig=None, do_db_compatibility_check=False
):
    code_versions = db_versions = None
    if upgrade_module:

        if do_db_compatibility_check and "do_db_compatibility_check" in dir(
            upgrade_module
        ):
            logger.info("DB compatibility check: running...")
            upgrade_module.do_db_compatibility_check()
            logger.info("DB compatibility check success")
        else:
            logger.info("DB compatibility check: skipping...")

        code_versions, db_versions = upgrade_module.get_versions()
        if code_versions and not db_versions:
            logger.info("DB not initialized: initializing tables...")
            upgrade_module.do_create_tables()
            upgrade_module.do_db_bootstrap(
                localconfig=localconfig,
                db_versions=db_versions,
                code_versions=code_versions,
            )
            # upgrade_module.do_version_update(db_versions, code_versions)
            code_versions, db_versions = upgrade_module.get_versions()

        if localconfig and "do_db_post_actions" in dir(upgrade_module):
            logger.info("DB post actions: running...")
            upgrade_module.do_db_post_actions(localconfig=localconfig)

    return code_versions, db_versions


def db_preflight(db_params: dict = None, db_retries=3):
    """
    Check the configuration and verify the db is running

    :param config:
    :param db_connect:
    :param db_use_ssl:
    :param db_timeout:
    :param db_connect_timeout:
    :param db_retries:
    :return:
    """
    # do some DB connection/pre-checks here
    connected_db_params = connect_database(db_params, db_retries=db_retries)
    return connected_db_params


def needs_upgrade(code_versions, db_versions):
    """
    Check if an upgrade is needed

    :param code_versions:
    :param db_versions:
    :return: None if no db upgrade needed, or tuple of (code db version (str), running db version (str)) if an upgrade is needed
    """

    code_db_version = code_versions.get("db_version", None)
    running_db_version = db_versions.get("db_version", None)

    if not code_db_version or not running_db_version:
        raise Exception(
            "cannot get version information (code_db_version=%s running_db_version=%s)",
            code_db_version,
            running_db_version,
        )

    if code_db_version == running_db_version:
        return None
    else:
        return code_db_version, running_db_version


def load_upgrade_module(module_name: str):
    """
    Load the named module, verifying it, and return it loaded

    :param module_name:
    :return:
    """
    try:
        logger.info("Loading DB upgrade routines from module %s", module_name)
        return importlib.import_module(module_name)
    except Exception as err:
        raise Exception(
            "Input module ("
            + str(module_name)
            + ") cannot be found/imported - exception: "
            + str(err)
        )


def upgrade_db(code_versions: dict, db_versions: dict, upgrade_module):
    """
    Run the upgrade process for the given module. Raises exception on errors, caller must handle end exit cleanly.
    Expects that the db has been initialized already via call to init_database() or similar

    :param code_versions: dict with versions for the code found installed
    :param db_versions: dict with versions for the versions found stored in the db (typically returned from init_database() call
    :param upgrade_module:
    :return: running db_version after upgrade
    """
    # Load the module for upgrade (provides the upgrade routines etc
    module = upgrade_module

    versions_tuple = needs_upgrade(code_versions, db_versions)
    if versions_tuple:
        code_db_version = versions_tuple[0]
        running_db_version = versions_tuple[1]
        logger.info(
            "Detected anchore-engine version %s, running DB version %s.",
            code_db_version,
            running_db_version,
        )
        logger.info("Performing upgrade.")

        # perform the upgrade logic here
        rc = module.run_upgrade()
        if rc:
            logger.info("Upgrade completed")
        else:
            logger.info("No upgrade necessary. Completed.")
    else:
        logger.info("Code and DB versions are in sync. No upgrade required")
        return True


def do_upgrade(skip_db_compat_check: False, no_auto_upgrade=False):
    """
    :param skip_db_compat_check: boole to indicate if a preflight check for the db engine type and version (e.g. postgres v9.6+) should be skipped
    :return:
    """

    upgrade_module = load_upgrade_module(ENGINE_UPGRADE_MODULE_NAME)
    code_versions, db_versions = init_database(
        upgrade_module=upgrade_module,
        do_db_compatibility_check=(not skip_db_compat_check),
    )
    if not no_auto_upgrade:
        upgrade_db(code_versions, db_versions, upgrade_module)
    return True
