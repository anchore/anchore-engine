import os
import click
import subprocess
import sys
import logging

import db, archivestorage, service
from anchore_manager import version
#import anchore_manager.clients
from . import utils

#from anchoreservice.subsys import logger

@click.group()
@click.option('--debug', is_flag=True, help='Debug output to stderr')
@click.option('--json', is_flag=True, help='Output raw API JSON')
@click.option('--configdir', help='Directory containing valid anchore-engine config.yaml')

@click.version_option(version=version.version)
@click.pass_context
#@extended_help_option(extended_help="extended help")
def main_entry(ctx, debug, json, configdir):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    cli_opts = {
        'json': json,
        'debug': debug,
        'configdir': configdir
    }

    config = utils.setup_config(cli_opts)
    if config['debug']:
        logging.basicConfig(level=logging.DEBUG)
        
    ctx.obj = config

main_entry.add_command(db.db)
main_entry.add_command(archivestorage.archivestorage)
main_entry.add_command(service.service)
