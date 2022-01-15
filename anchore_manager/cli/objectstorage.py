import copy
import datetime
import json

import click
import yaml
from prettytable import PLAIN_COLUMNS, PrettyTable

from anchore_engine.configuration.localconfig import get_config, load_config
from anchore_engine.db import ArchiveMigrationTask, db_tasks, session_scope
from anchore_engine.subsys import object_store
from anchore_engine.subsys.object_store import config as obj_config
from anchore_engine.subsys.object_store import migration
from anchore_engine.subsys.object_store.config import (
    ALT_OBJECT_STORE_CONFIG_KEY,
    ANALYSIS_ARCHIVE_MANAGER_ID,
    DEFAULT_OBJECT_STORE_MANAGER_ID,
)
from anchore_manager.util.db import db_context, db_preflight, init_db_context
from anchore_manager.util.logging import log_error, logger
from anchore_manager.util.proc import ExitCode, doexit, fail_exit

config = {}
module = None


@click.group(name="objectstorage", short_help="Object Storage operations")
@click.option(
    "--db-connect", nargs=1, required=True, help="DB connection string override."
)
@click.option("--db-use-ssl", is_flag=True, help="Set if DB connection is using SSL.")
@click.option(
    "--db-retries",
    nargs=1,
    default=1,
    type=int,
    help="If set, the tool will retry to connect to the DB the specified number of times at 5 second intervals.",
)
@click.option(
    "--db-timeout",
    nargs=1,
    default=30,
    type=int,
    help="Number of seconds to wait for DB call to complete before timing out.",
)
@click.option(
    "--db-connect-timeout",
    nargs=1,
    default=120,
    type=int,
    help="Number of seconds to wait for initial DB connection before timing out.",
)
@click.pass_obj
def objectstorage(
    ctx_config, db_connect, db_use_ssl, db_retries, db_timeout, db_connect_timeout
):
    global config
    config = ctx_config

    try:
        init_db_context(
            db_connect, db_use_ssl, db_timeout, db_connect_timeout, db_retries
        )
    except Exception as err:
        log_error("objectstorage", err)
        fail_exit()


@objectstorage.command(
    name="list-drivers",
    short_help="Show a list of available drivers that can be a source or destination for conversion.",
)
def list_drivers():
    """
    List the available drivers installed locally
    """

    ecode = ExitCode.ok

    try:
        drivers = object_store.manager.get_driver_list()
        logger.info("Supported object storage drivers: " + str(drivers))
    except Exception as err:
        log_error("list-drivers", err)
        if not ecode:
            ecode = ExitCode.failed

    doexit(ecode)


@objectstorage.command(name="check")
@click.argument("configfile", type=click.Path(exists=True))
@click.option(
    "--analysis-archive",
    is_flag=True,
    default=False,
    help="Migrate using the analysis archive sections of the configuration files, not the object store. This is intended to migrate the analysis archive itself",
)
def check(configfile, analysis_archive):
    """
    Test the configuration in the expected anchore-engine config location or override that and use the configuration file provided as an option.

    To test, the system will read and write a very small data document to the driver and then delete it on completion.
    """

    db_conf = db_context()
    db_preflight(db_conf["params"], db_conf["retries"])

    logger.info("Using config file {}".format(configfile))
    sys_config = load_config(configfile=configfile)

    if sys_config:
        service_config = sys_config["services"]["catalog"]
    else:
        service_config = None

    if not service_config:
        logger.info(
            "No configuration file or content available. Cannot test archive driver configuration"
        )
        fail_exit()

    if analysis_archive:
        try:
            object_store.initialize(
                service_config,
                manager_id=ANALYSIS_ARCHIVE_MANAGER_ID,
                config_keys=[ANALYSIS_ARCHIVE_MANAGER_ID],
            )
        except:
            logger.error(
                'No "analysis_archive" configuration section found in the configuration. To check a config that uses the default backend for analysis archive data, use the regular object storage check'
            )
            fail_exit()

        mgr = object_store.get_manager(ANALYSIS_ARCHIVE_MANAGER_ID)
    else:
        object_store.initialize(
            service_config,
            manager_id=DEFAULT_OBJECT_STORE_MANAGER_ID,
            config_keys=[DEFAULT_OBJECT_STORE_MANAGER_ID, ALT_OBJECT_STORE_CONFIG_KEY],
        )
        mgr = object_store.get_manager()

    test_user_id = "test"
    test_bucket = "anchorecliconfigtest"
    test_archive_id = "cliconfigtest"
    test_data = "clitesting at {}".format(datetime.datetime.utcnow().isoformat())

    logger.info(
        "Checking existence of test document with user_id = {}, bucket = {} and archive_id = {}".format(
            test_user_id, test_bucket, test_archive_id
        )
    )
    if mgr.exists(test_user_id, test_bucket, test_archive_id):
        test_archive_id = "cliconfigtest2"
        if mgr.exists(test_user_id, test_bucket, test_archive_id):
            logger.error(
                "Found existing records for archive doc to test, aborting test to avoid overwritting any existing data"
            )
            doexit(1)

    logger.info(
        "Creating test document with user_id = {}, bucket = {} and archive_id = {}".format(
            test_user_id, test_bucket, test_archive_id
        )
    )
    result = mgr.put(test_user_id, test_bucket, test_archive_id, data=test_data)
    if not result:
        logger.warn("Got empty response form archive PUT operation: {}".format(result))

    logger.info("Checking document fetch")
    loaded = str(mgr.get(test_user_id, test_bucket, test_archive_id), "utf-8")
    if not loaded:
        logger.error("Failed retrieving the written document. Got: {}".format(loaded))
        doexit(ExitCode.obj_store_failed)

    if str(loaded) != test_data:
        logger.error(
            'Failed retrieving the written document. Got something other than expected. Expected: "{}" Got: "{}"'.format(
                test_data, loaded
            )
        )
        doexit(ExitCode.obj_store_failed)

    logger.info("Removing test object")
    mgr.delete(test_user_id, test_bucket, test_archive_id)

    if mgr.exists(test_user_id, test_bucket, test_archive_id):
        logger.error("Found archive object after it should have been removed")
        doexit(ExitCode.obj_store_failed)

    logger.info("Archive config check completed successfully")


@objectstorage.command(
    name="migrate", short_help="Convert between archive storage driver formats."
)
@click.argument("from-driver-configpath", type=click.Path(exists=True))
@click.argument("to-driver-configpath", type=click.Path(exists=True))
@click.option(
    "--from-analysis-archive",
    is_flag=True,
    help="Migrate using the analysis archive sections of the configuration files, not the object store. This is intended to migrate the analysis archive itself",
)
@click.option(
    "--to-analysis-archive",
    is_flag=True,
    help="Migrate using the analysis archive sections of the configuration files, not the object store. This is intended to migrate the analysis archive itself",
)
@click.option(
    "--nodelete",
    is_flag=True,
    help="If set, leaves the document in the source driver location rather than removing after successful migration. May require manual removal of the data after migration.",
)
@click.option(
    "--dontask",
    is_flag=True,
    help="Perform conversion (if necessary) without prompting.",
)
@click.option(
    "--bucket",
    multiple=True,
    help="A specific logical bucket of data to migrate. Can be specified multiple times for multiple buckets. Note: this is NOT the bucket name on the backend, only the internal logical bucket anchore uses to organize its data. This should not usually be needed and should be used very carefully. E.g. analysis_archive, manifest_data, image_content_data, ...",
)
def migrate(
    from_driver_configpath,
    to_driver_configpath,
    from_analysis_archive=False,
    to_analysis_archive=False,
    nodelete=False,
    dontask=False,
    bucket=None,
):
    """
    Migrate the objects in the document archive from one driver backend to the other. This may be a long running operation depending on the number of objects and amount of data to migrate.

    The migration process expects that the source and destination configurations are provided by config files passed in as arguments. The source configuration generally should be the same
    as the configuration in the anchore engine config.yaml.

    The general flow for a migration is:
    1. Stop anchore-engine services (shutdown the entire cluster to ensure no data modifications during migration)
    2. Create a new configuration yaml with at minimum the services.catalog.archive section configured as you would like it when migraton is complete
    3. Run migration
    4. Update the config.yaml for you anchore-engine system to use the new driver.
    5. Start anchore-engine again

    """

    ecode = ExitCode.ok

    do_migrate = False
    try:
        db_conf = db_context()
        db_preflight(db_conf["params"], db_conf["retries"])

        logger.info("Loading configs")
        from_raw = copy.deepcopy(load_config(configfile=from_driver_configpath))
        get_config().clear()

        to_raw = copy.deepcopy(load_config(configfile=to_driver_configpath))

        if from_analysis_archive:
            # Only use the specific key for the source, fail if not found
            from_config = obj_config.extract_config(
                from_raw["services"]["catalog"],
                config_keys=[ANALYSIS_ARCHIVE_MANAGER_ID],
            )
        else:
            from_config = obj_config.extract_config(
                from_raw["services"]["catalog"],
                config_keys=[
                    DEFAULT_OBJECT_STORE_MANAGER_ID,
                    ALT_OBJECT_STORE_CONFIG_KEY,
                ],
            )

        if from_config:
            from_config = obj_config.normalize_config(
                from_config, legacy_fallback=False
            )
            logger.info(
                "Migration from config: {}".format(json.dumps(from_config, indent=2))
            )
        else:
            if from_analysis_archive:
                config_key = ANALYSIS_ARCHIVE_MANAGER_ID
            else:
                config_key = (
                    '"'
                    + DEFAULT_OBJECT_STORE_MANAGER_ID
                    + '" or "'
                    + ALT_OBJECT_STORE_CONFIG_KEY
                    + '"'
                )
            raise Exception(
                "No valid source configuration found. Needed a configuration section with key {} in the catalog service key".format(
                    config_key
                )
            )

        if to_analysis_archive:
            # Only use the specific key if set, fail if not found
            to_config = obj_config.extract_config(
                to_raw["services"]["catalog"], config_keys=[ANALYSIS_ARCHIVE_MANAGER_ID]
            )
        else:
            to_config = obj_config.extract_config(
                to_raw["services"]["catalog"],
                config_keys=[
                    DEFAULT_OBJECT_STORE_MANAGER_ID,
                    ALT_OBJECT_STORE_CONFIG_KEY,
                ],
            )

        if to_config:
            logger.info(
                "Migration to config: {}".format(json.dumps(to_config, indent=2))
            )
            to_config = obj_config.normalize_config(to_config, legacy_fallback=False)
        else:
            if to_analysis_archive:
                config_key = '"' + ANALYSIS_ARCHIVE_MANAGER_ID + '"'
            else:
                config_key = (
                    '"'
                    + DEFAULT_OBJECT_STORE_MANAGER_ID
                    + '" or "'
                    + ALT_OBJECT_STORE_CONFIG_KEY
                    + '"'
                )
            raise Exception(
                "No valid destination configuration found. Needed a configuration section with key {} in the catalog service key".format(
                    config_key
                )
            )

        if dontask:
            do_migrate = True
        else:
            try:
                answer = input(
                    "Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)"
                )
            except:
                answer = "n"
            if "y" == answer.lower():
                do_migrate = True

        if do_migrate:
            migration.initiate_migration(
                from_config,
                to_config,
                remove_on_source=(not nodelete),
                do_lock=True,
                buckets_to_migrate=bucket,
            )
            logger.info(
                "After this migration, your anchore-engine config.yaml MUST have the following configuration options added before starting up again:"
            )
            if "archive_data_dir" in to_config:
                logger.info(
                    "\tNOTE: for archive_data_dir, the value must be set to the location that is accessible within your anchore-engine container"
                )

            logger.info((yaml.dump(to_config, default_flow_style=False)))
        else:
            logger.info("Skipping conversion.")
    except Exception as err:
        log_error("migrate", err)
        fail_exit()

    doexit(ecode)


@objectstorage.command(
    name="list-migrations",
    short_help="List any previous migrations and their results/status",
)
def list_migrations():
    db_conf = db_context()
    db_preflight(db_conf["params"], db_conf["retries"])

    with session_scope() as db:
        tasks = db_tasks.get_all(
            task_type=ArchiveMigrationTask, session=db, json_safe=True
        )

    fields = [
        "id",
        "state",
        "started_at",
        "ended_at",
        "migrate_from_driver",
        "migrate_to_driver",
        "archive_documents_migrated",
        "archive_documents_to_migrate",
        "last_updated",
    ]

    headers = [
        "id",
        "state",
        "start time",
        "end time",
        "from",
        "to",
        "migrated count",
        "total to migrate",
        "last updated",
    ]

    tbl = PrettyTable(field_names=headers)
    tbl.set_style(PLAIN_COLUMNS)
    for t in tasks:
        tbl.add_row([t[x] for x in fields])

    logger.info((tbl.get_string(sortby="id")))
