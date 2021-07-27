import click

from anchore_manager import version
from anchore_manager.util import logging
from anchore_manager.util.config import setup_config

from . import analyzers, db, objectstorage, service


@click.group()
@click.option("--debug", is_flag=True, help="Debug output to stderr")
@click.option("--json", is_flag=True, help="Output raw API JSON")
@click.option(
    "--configdir", help="Directory containing valid anchore-engine config.yaml"
)
@click.version_option(version=version.version)
@click.pass_context
def main_entry(ctx, debug, json, configdir):
    cli_opts = {"json": json, "debug": debug, "configdir": configdir}
    config = setup_config(cli_opts)
    logging.log_config(config)
    ctx.obj = config


main_entry.add_command(db.db)
main_entry.add_command(objectstorage.objectstorage)
main_entry.add_command(service.service)
main_entry.add_command(analyzers.analyzers)
