import json
import sys
import click

from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig
from anchore_engine.clients import localanchore_standalone
from anchore_engine.clients.skopeo_wrapper import get_image_manifest_skopeo

import anchore_manager.cli.utils

config = {}
module = None

@click.group()
@click.pass_obj
def analyzers(ctx_config):
    global config, module
    config = localconfig.load_config(configdir=ctx_config['configdir'])

    try:
        # do some DB connection/pre-checks here
        try:

            log_level = 'INFO'
            if ctx_config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)
        except Exception as err:
            raise err

    except Exception as err:
        logger.error(anchore_manager.cli.utils.format_error_output(ctx_config, 'db', {}, err))
        sys.exit(2)


@analyzers.command()
def list():
    """
    List available analyzers on the local host
    :return:
    """

    click.echo('Installed analyzers')
    for l in localanchore_standalone.list_analyzers():
        click.echo('Analyzer: {}'.format(l))

@analyzers.command()
@click.argument('tag')
@click.option('--tmpdir', default='/tmp', help='Location of temp dir to use', type=click.Path(exists=True, dir_okay=True))
def exec(tag, tmpdir):
    """
    Run analyzer(s) against the local tagged image and write the result in a local fs
    :param tag: str tag name to analyze on local host (e.g. alpine:latest)
    :param tmpdir: valid and existing file path
    :return:
    """
    global config
    click.echo('Getting tag manifest for: {}'.format(tag))
    registry, rest = tag.split('/', 1)
    repo, tag = rest.split(':', 1)
    click.echo('Registry: {}, Repository: {}, Tag: {}'.format(registry, repo, tag))
    manifest, digest, parentdigest = get_image_manifest_skopeo(None, registry, repo, intag=tag)
    img_record = {
        'imageDigest': digest,
        'parentDigest': parentdigest,
        'dockerfile_mode': 'guessed',
        'image_detail': [
            {
                'dockerfile': '',
                'imageId': digest,
                'imageDigest': digest,
                'tag': tag,
                'registry': registry,
                'repo': repo
            }
        ]
    }
    click.echo('Got digest: {}'.format(digest))
    click.echo('Got parentdigest: {}'.format(parentdigest))
    click.echo('Config: {}'.format(config))
    click.echo('Running analyzers')

    image_report = localanchore_standalone.analyze_image(userId='cli_test',
                                          manifest=json.dumps(manifest),
                                          image_record=img_record,
                                          tmprootdir=tmpdir,
                                          localconfig=config,
                                          registry_creds=None,
                                          use_cache_dir=False
                                          )
    click.echo('complete!')
    with open(digest + '.report.json', 'w') as f:
        json.dump(image_report, f)

