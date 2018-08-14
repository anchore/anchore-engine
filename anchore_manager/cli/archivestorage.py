import copy
import json
import sys
import yaml
import click
import datetime
import os
from prettytable import PrettyTable, PLAIN_COLUMNS

from anchore_engine.subsys import archive
from anchore_engine.subsys import logger
from anchore_engine.configuration.localconfig import load_config, get_config
from anchore_engine.subsys.archive import migration, operations
from anchore_engine.db import db_tasks, ArchiveMigrationTask, session_scope
from anchore_manager.cli import utils

config = {}
localconfig = None
module = None

@click.group(name='archivestorage', short_help='Archive Storage operations')
@click.option('--configfile', type=click.Path(exists=True))
@click.option("--db-connect", nargs=1, required=True, help="DB connection string override.")
@click.option("--db-use-ssl", is_flag=True, help="Set if DB connection is using SSL.")
@click.option("--db-retries", nargs=1, default=1, type=int, help="If set, the tool will retry to connect to the DB the specified number of times at 5 second intervals.")
@click.option("--db-timeout", nargs=1, default=30, type=int, help="Number of seconds to wait for DB call to complete before timing out.")
@click.option("--db-connect-timeout", nargs=1, default=120, type=int, help="Number of seconds to wait for initial DB connection before timing out.")
@click.pass_obj
def archivestorage(ctx_config , configfile, db_connect, db_use_ssl, db_retries, db_timeout, db_connect_timeout):
    global config, localconfig
    config = ctx_config

    try:
        # do some DB connection/pre-checks here
        try:
            localconfig = {
                'services': {
                    'catalog': {
                        'use_db': True,
                        'archive_driver': 'db',
                        'archive_data_dir': None
                    }
                }
            }

            log_level = 'INFO'
            if config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)

            # Use db connection from the config file
            db_params = utils.make_db_params(db_connect=db_connect, db_use_ssl=db_use_ssl, db_timeout=db_timeout, db_connect_timeout=db_connect_timeout)
            db_params = utils.connect_database(config, db_params, db_retries=db_retries)
        except Exception as err:
            raise err

    except Exception as err:
        logger.error(utils.format_error_output(config, 'archivestorage', {}, err))
        sys.exit(2)


@archivestorage.command(name="list-drivers", short_help="Show a list of available drivers that can be a source or destination for conversion.")
def list_drivers():
    """
    """
    ecode = 0

    try:
        drivers = archive.get_driver_list()
        logger.info("Supported convertable drivers: " + str(drivers))
    except Exception as err:
        logger.error(utils.format_error_output(config, 'dbupgrade', {}, err))
        if not ecode:
            ecode = 2

    utils.doexit(ecode)


@archivestorage.command(name='check')
@click.argument("configfile", type=click.Path(exists=True))
def check(configfile):
    """
    Test the configuration in the expected anchore-engine config location or override that and use the configuration file provided as an option.

    To test, the system will read and write a very small data document to the driver and then delete it on completion.

    :param configfile:
    :return:
    """

    logger.info('Using config file {}'.format(configfile))
    sys_config = load_config(configfile=configfile)

    if sys_config:
        service_config = sys_config['services']['catalog']
    else:
        service_config = None

    if not service_config:
        logger.error('No configuration file or content available. Cannot test archive driver configuration')
        utils.doexit(2)

    archive.initialize(service_config)

    test_user_id = 'test'
    test_bucket = 'anchorecliconfigtest'
    test_archive_id = 'cliconfigtest'
    test_data = 'clitesting at {}'.format(datetime.datetime.utcnow().isoformat())

    logger.info('Checking existence of test document with user_id = {}, bucket = {} and archive_id = {}'.format(test_user_id, test_bucket,
                                                                                             test_archive_id))
    if archive.exists(test_user_id, test_bucket, test_archive_id):
        test_archive_id = 'cliconfigtest2'
        if archive.exists(test_user_id, test_bucket, test_archive_id):
            logger.error('Found existing records for archive doc to test, aborting test to avoid overwritting any existing data')
            utils.doexit(1)

    logger.info('Creating test document with user_id = {}, bucket = {} and archive_id = {}'.format(test_user_id, test_bucket,
                                                                                             test_archive_id))
    result = archive.put(test_user_id, test_bucket, test_archive_id, data=test_data)
    if not result:
        logger.warn('Warning: Got empty response form archive PUT operation: {}'.format(result))

    logger.info('Checking document fetch')
    loaded = str(archive.get(test_user_id, test_bucket, test_archive_id), 'utf-8')
    if not loaded:
        logger.error('Failed retrieving the written document. Got: {}'.format(loaded))
        utils.doexit(5)

    if str(loaded) != test_data:
        logger.error('Failed retrieving the written document. Got something other than expected. Expected: "{}" Got: "{}"'.format(test_data, loaded))
        utils.doexit(5)

    logger.info('Removing test object')
    archive.delete(test_user_id, test_bucket, test_archive_id)

    if archive.exists(test_user_id, test_bucket, test_archive_id):
        logger.error('Found archive object after it should have been removed')
        utils.doexit(5)

    logger.info('Archive config check completed successfully')


@archivestorage.command(name='migrate', short_help="Convert between archive storage driver formats.")
@click.argument("from-driver-configpath", type=click.Path(exists=True))
@click.argument("to-driver-configpath", type=click.Path(exists=True))
@click.option('--nodelete', is_flag=True, help='If set, leaves the document in the source driver location rather than removing after successful migration. May require manual removal of the data after migration.')
@click.option("--dontask", is_flag=True, help="Perform conversion (if necessary) without prompting.")
def migrate(from_driver_configpath, to_driver_configpath, nodelete=False, dontask=False):
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
    global localconfig

    ecode = 0
    do_migrate = False
    try:
        logger.info('Loading configs')
        from_raw = copy.deepcopy(load_config(configfile=from_driver_configpath))
        get_config().clear()

        to_raw = copy.deepcopy(load_config(configfile=to_driver_configpath))
        get_config().clear()

        from_config = operations.normalize_config(from_raw['services']['catalog'])
        to_config = operations.normalize_config(to_raw['services']['catalog'])

        logger.info('Migration from config: {}'.format(json.dumps(from_config, indent=2)))
        logger.info('Migration to config: {}'.format(json.dumps(to_config, indent=2)))

        if dontask:
            do_migrate = True
        else:
            try:
                answer = input("Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)")
            except:
                answer = "n"
            if 'y' == answer.lower():
                do_migrate = True

        if do_migrate:
            migration.initiate_migration(from_config, to_config, remove_on_source=(not nodelete), do_lock=True)
            logger.info("After this migration, your anchore-engine config.yaml MUST have the following configuration options added before starting up again:")
            if 'archive_data_dir' in to_config:
                logger.info("\tNOTE: for archive_data_dir, the value must be set to the location that is accessible within your anchore-engine container")

            print((yaml.dump(to_config, default_flow_style=False)))
        else:
            logger.info("Skipping conversion.")
    except Exception as err:
        logger.error(utils.format_error_output(config, 'dbupgrade', {}, err))
        if not ecode:
            ecode = 2

    utils.doexit(ecode)

@archivestorage.command(name='list-migrations', short_help="List any previous migrations and their results/status")
def list_migrations():

    with session_scope() as db:
        tasks = db_tasks.get_all(task_type=ArchiveMigrationTask, session=db, json_safe=True)

    fields = [
        'id',
        'state',
        'started_at',
        'ended_at',
        'migrate_from_driver',
        'migrate_to_driver',
        'archive_documents_migrated',
        'archive_documents_to_migrate',
        'last_updated'
    ]

    headers = [
        'id',
        'state',
        'start time',
        'end time',
        'from',
        'to',
        'migrated count',
        'total to migrate',
        'last updated'
    ]

    tbl = PrettyTable(field_names=headers)
    tbl.set_style(PLAIN_COLUMNS)
    for t in tasks:
        tbl.add_row([t[x] for x in fields])

    print((tbl.get_string(sortby='id')))
