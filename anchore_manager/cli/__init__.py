import click

from . import db, objectstorage, service, analyzers
from anchore_manager import version
from anchore_manager.util.config import init_all


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

    config = init_all(cli_opts)
    ctx.obj = config


main_entry.add_command(db.db)
main_entry.add_command(objectstorage.objectstorage)
main_entry.add_command(service.service)
main_entry.add_command(analyzers.analyzers)
