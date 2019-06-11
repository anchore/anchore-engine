import json
import sys
import click
import time
import base64
import re
import random
import os

from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig
from anchore_engine.clients import localanchore_standalone
from anchore_engine.clients.skopeo_wrapper import get_image_manifest_skopeo
from anchore_engine.common.images import make_image_record
from anchore_engine.clients.localanchore_standalone import analyze_image
from anchore_engine.services.catalog.archiver import ImageArchive, ObjectStoreLocation
from anchore_engine.utils import ensure_str, ensure_bytes, parse_dockerimage_string, manifest_to_digest
import anchore_engine.common.helpers

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
@click.argument('docker-archive', type=click.Path(exists=True))
@click.argument('anchore-archive')
@click.option('--digest', help="Specify image digest (ex: sha256:<64 hex characters>)")
@click.option('--parent-digest', help="Specify parent digest (ex: sha256:<64 hex characters>). Default is same as image digest.")
@click.option('--image-id', help="Specify image ID (ex: <64 hex characters>)")
@click.option('--tag', help="Specify image full tag (ex: docker.io/somerepo:latest)")
@click.option('--account-id', help="Specify anchore account ID (ex: admin)")
@click.option('--manifest', type=click.Path(exists=True), help="Specify location of image manifest file")
@click.option('--dockerfile', type=click.Path(exists=True), help="Specify location of Dockerfile used to build image")
@click.option('--annotation', nargs=1, multiple=True, help="Set annotation key/val (ex: foo=bar)")
def exec(docker_archive, anchore_archive, digest, parent_digest, image_id, tag, account_id, manifest, dockerfile, annotation):
    """
    Analyze a local image stored as a docker archive (output result of 'docker save'), and generate an anchore image archive tarball ready for import into an anchore engine.

    DOCKER_ARCHIVE : Location of input docker archive tarfile to analyze
    ANCHORE_ARCHIVE : Location of output anchore image archive to write

    """

    global config

    # this could be improved to allow use to input timestamps (created_at, analyzed_at, etc)
    now = int(time.time())

    try:
        imageDigest = None
        manifest_data = None
        rawmanifest = None

        if (not manifest and not digest) or (manifest and digest):
            raise Exception("must supply either an image digest, or a valid manifest, but not both")

        if os.path.exists(anchore_archive):
            raise Exception("the supplied anchore archive file ({}) already exists, please remove and try again".format(anchore_archive))

        if manifest:
            with open(manifest, 'r') as FH:
                # TODO implement manifest validator for anchore requirements, specifically
                rawmanifest = FH.read()
                input_manifest_data = json.loads(rawmanifest)
                #manifest_data = json.loads(rawmanifest)
                imageDigest = manifest_to_digest(rawmanifest)

        if not imageDigest:
            if digest:
                if re.match("^sha256:[\d|a-f]{64}$", digest):
                    imageDigest = digest
                else:
                    raise ValueError("input digest does not validate")
            else:
                imageDigest = "sha256:{}".format(''.join([random.choice('0123456789abcdef') for x in range(0,64)]))

        if parent_digest:
            if re.match("^sha256:[\d|a-f]{64}$", parent_digest):
                parentDigest = parent_digest
            else:
                raise ValueError("input parent_digest does not validate")
        else:
            parentDigest = imageDigest

        if image_id:
            if re.match("^[\d|a-f]{64}$", image_id):
                imageId = image_id
            else:
                raise ValueError("input user_id does not validate")
        else:
            # TODO this could be improved to generate imageId from configuration hash
            imageId = "{}".format(''.join([random.choice('0123456789abcdef') for x in range(0,64)]))

        if account_id:
            userId = account_id
        else:
            userId = 'admin'

        if tag:
            inputTag = tag
        else:
            inputTag = "anchore/local:latest_{}".format(int(time.time()))

        image_info = parse_dockerimage_string(inputTag)
        fulltag = "{}/{}:{}".format(image_info['registry'], image_info['repo'], image_info['tag'])
        fulldigest = "{}/{}@{}".format(image_info['registry'], image_info['repo'], imageDigest)

        dockerfile_mode="Guessed"
        dockerfile_contents = None
        if dockerfile:
            with open(dockerfile, 'r') as FH:
                dockerfile_contents = ensure_str(base64.b64encode(ensure_bytes(FH.read())))
                dockerfile_mode = "Actual"

        annotations = {}
        if annotation:
            for a in annotation:
                try:
                    (k,v) = a.split('=', 1)
                    if k and v:
                        annotations[k] = v
                    else:
                        raise Exception("found null in key or value")
                except Exception as err:
                    raise Exception("annotation format error - annotations must be of the form (--annotation key=value), found: {}".format(a))

        created_at = now
        workspace_root = config['tmp_dir']
    except Exception as err:
        # input setup/validation failure
        raise err

    logger.debug("input has been prepared: imageDigest={} parentDigest={} imageId={} inputTag={} fulltag={} fulldigest={} userId={} annotations={} created_at={}".format(imageDigest, parentDigest, imageId, inputTag, fulltag, fulldigest, userId, annotations, created_at))

    # create an image record
    try:
        image_record = make_image_record(userId, 'docker', None, image_metadata={'tag':fulltag, 'digest':fulldigest, 'imageId':imageId, 'parentdigest': parentDigest, 'created_at': created_at, 'dockerfile':dockerfile_contents, 'dockerfile_mode': dockerfile_mode, 'annotations': annotations}, registry_lookup=False, registry_creds=(None, None))
        image_record['created_at'] = now
        image_record['last_updated'] = now
        image_record['analyzed_at'] = now
        image_record['analysis_status'] = 'analyzed'
        image_record['image_status'] = 'active'
        image_record['record_state_key'] = 'active'
        for image_detail in image_record['image_detail']:
            image_detail['created_at'] = now
            image_detail['last_updated'] = now
            image_detail['tag_detected_at'] = now
            image_detail['record_state_key'] = 'active'                 
    except Exception as err:
        # image record setup fail
        raise err

    # perform analysis
    try:
        image_data, analyzed_manifest_data = analyze_image(userId, rawmanifest, image_record, workspace_root, config, registry_creds=[], use_cache_dir=None, image_source='docker-archive', image_source_meta=docker_archive)

        image_content_data = {}
        for content_type in anchore_engine.common.image_content_types + anchore_engine.common.image_metadata_types:
            try:
                image_content_data[content_type] = anchore_engine.common.helpers.extract_analyzer_content(image_data, content_type, manifest=input_manifest_data)
            except:
                image_content_data[content_type] = {}

        anchore_engine.common.helpers.update_image_record_with_analysis_data(image_record, image_data)
        image_record['image_size'] = int(image_record['image_size'])
    except Exception as err:
        # image analysis fail
        raise err

    # generate an output image archive tarball
    archive_file = anchore_archive
    try:
        with ImageArchive.for_writing(archive_file) as img_archive:

            img_archive.account = userId
            img_archive.image_digest = imageDigest
            img_archive.manifest.metadata = {
                'versions': localconfig.get_versions(),
                'image_id': imageId,
                'image_record': json.dumps(image_record, sort_keys=True)
            }

            pack_data = {'document': image_data}
            data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
            img_archive.add_artifact('analysis', source=ObjectStoreLocation(bucket='analysis_data', key=imageDigest), data=data, metadata=None)

            pack_data = {'document': image_content_data}
            data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
            img_archive.add_artifact('image_content', source=ObjectStoreLocation(bucket='image_content_data', key=imageDigest), data=data, metadata=None)

            pack_data = {'document': input_manifest_data}
            data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
            img_archive.add_artifact('image_manifest', source=ObjectStoreLocation(bucket='manifest_data', key=imageDigest), data=data, metadata=None)
    except Exception as err:
        # archive tarball generate fail
        raise err
    
    click.echo("Analysis complete - archive file is located at {}".format(archive_file))
#    finally:
#        try:
#            if os.path.exists(archive_file):
#                os.remove(archive_file)
#        except:
#            pass



@analyzers.command()
@click.argument('tag')
@click.option('--tmpdir', default='/tmp', help='Location of temp dir to use', type=click.Path(exists=True, dir_okay=True))
def exec_orig(tag, tmpdir):
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

    image_report, manifest_raw = localanchore_standalone.analyze_image(userId='cli_test',
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

