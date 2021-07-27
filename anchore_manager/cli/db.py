import click

from anchore_engine.subsys import logger
from anchore_manager.util.db import (
    db_context,
    db_preflight,
    do_upgrade,
    init_db_context,
)
from anchore_manager.util.logging import log_error
from anchore_manager.util.proc import ExitCode, doexit, fail_exit

config = {}
module = None


@click.group(name="db", short_help="DB operations")
@click.pass_obj
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
    default=86400,
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
def db(ctx_config, db_connect, db_use_ssl, db_retries, db_timeout, db_connect_timeout):
    global config, module
    config = ctx_config

    try:
        init_db_context(
            db_connect, db_use_ssl, db_timeout, db_connect_timeout, db_retries
        )
    except Exception as err:
        log_error("objectstorage", err)
        fail_exit()


@db.command(
    name="upgrade",
    short_help="Upgrade DB to version compatible with installed anchore-engine code.",
)
@click.option(
    "--dontask", is_flag=True, help="Perform upgrade (if necessary) without prompting."
)
@click.option(
    "--skip-db-compat-check",
    is_flag=True,
    help="Skip the database compatibility check.",
)
def upgrade(dontask, skip_db_compat_check):

    """
    Run a Database Upgrade idempotently. If database is not initialized yet, but can be connected, then exit cleanly with status = 0, if no connection available then return error.
    Otherwise, upgrade from the db running version to the code version and exit.

    """
    if not dontask:
        try:
            answer = input(
                "Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)"
            )
        except:
            answer = "n"
        if "y" != answer.lower():
            logger.info("Skipping upgrade")
            doexit(ExitCode.ok)

    try:
        db_conf = db_context()
        db_preflight(db_conf["params"], db_conf["retries"])

        do_upgrade(skip_db_compat_check)
        doexit(ExitCode.ok)
    except Exception as err:
        log_error("dbupgrade", err)
        fail_exit()
