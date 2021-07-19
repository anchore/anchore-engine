import base64
import json
import os
import random
import re
import time

import click

import anchore_engine.common.helpers
from anchore_engine.clients import localanchore_standalone
from anchore_engine.clients.localanchore_standalone import analyze_image
from anchore_engine.clients.skopeo_wrapper import manifest_to_digest
from anchore_engine.common.images import make_image_record
from anchore_engine.configuration import localconfig
from anchore_engine.services.catalog.archiver import ImageArchive, ObjectStoreLocation
from anchore_engine.util.docker import parse_dockerimage_string
from anchore_engine.utils import ensure_bytes, ensure_str
from anchore_manager.util.logging import log_error, logger
from anchore_manager.util.proc import fail_exit

config = {}
click_config = {}
module = None


@click.group()
@click.pass_obj
def analyzers(ctx_config):
    global config, module, click_config

    config = localconfig.load_config(configdir=ctx_config["configdir"])
    click_config = ctx_config


@analyzers.command()
def list():
    """
    List available analyzers on the local host
    :return:
    """

    click.echo("Installed analyzers")
    for l in localanchore_standalone.list_analyzers():
        click.echo("Analyzer: {}".format(l))


@analyzers.command()
@click.argument("docker-archive", type=click.Path(exists=True))
@click.argument("anchore-archive", type=click.Path(exists=False, dir_okay=False))
@click.option("--digest", help="Specify image digest (ex: sha256:<64 hex characters>)")
@click.option(
    "--parent-digest",
    help="Specify parent digest (ex: sha256:<64 hex characters>, default: <supplied or calculated image digest>",
)
@click.option("--image-id", help="Specify image ID (ex: <64 hex characters>)")
@click.option(
    "--tag",
    help="Specify image full tag (ex: docker.io/somerepo:latest)",
    required=True,
)
@click.option(
    "--account-id",
    help="Specify anchore account ID of the image (ex: admin, default: admin)",
)
@click.option(
    "--manifest",
    type=click.Path(exists=True),
    help="Specify location of image manifest file (schema v2, not manifest list)",
)
@click.option(
    "--dockerfile",
    type=click.Path(exists=True),
    help="Specify location of Dockerfile used to build image",
)
@click.option(
    "--created_at",
    help="UNIX timestamp to store when image was created (ex: 1560454880, default: now)",
)
@click.option(
    "--annotation", nargs=1, multiple=True, help="Set annotation key/val (ex: foo=bar)"
)
def exec(
    docker_archive,
    anchore_archive,
    digest,
    parent_digest,
    image_id,
    tag,
    account_id,
    manifest,
    dockerfile,
    created_at,
    annotation,
):
    """
    Analyze a local image stored as a docker archive (output result of 'docker save'), and generate an anchore image archive tarball ready for import into an anchore engine.

    DOCKER_ARCHIVE : Location of input docker archive tarfile to analyze
    ANCHORE_ARCHIVE : Location of output anchore image archive to write

    """

    global config

    # this could be improved to allow use to input timestamps (created_at, analyzed_at, etc)
    now = int(time.time())
    try:
        try:
            imageDigest = None
            input_manifest_data = None
            rawmanifest = None

            if (not manifest and not digest) or (manifest and digest):
                raise Exception(
                    "must supply either an image digest or a valid manifest, but not both"
                )

            if os.path.exists(anchore_archive):
                raise Exception(
                    "the supplied anchore archive file ({}) already exists, please remove and try again".format(
                        anchore_archive
                    )
                )

            if manifest:
                try:
                    with open(manifest, "r") as FH:
                        # TODO implement manifest validator for anchore requirements, specifically
                        rawmanifest = FH.read()
                        input_manifest_data = json.loads(rawmanifest)
                        imageDigest = manifest_to_digest(rawmanifest)
                except Exception as err:
                    raise ValueError(
                        "cannot calculate digest from supplied manifest - exception: {}".format(
                            err
                        )
                    )

            if digest:
                if re.match("^sha256:[\d|a-f]{64}$", digest):
                    imageDigest = digest
                else:
                    raise ValueError(
                        "input digest does not validate - must be sha256:<64 hex characters>"
                    )

            if parent_digest:
                if re.match("^sha256:[\d|a-f]{64}$", parent_digest):
                    parentDigest = parent_digest
                else:
                    raise ValueError(
                        "input parent_digest does not validate - must be sha256:<64 hex characters>"
                    )
            else:
                parentDigest = imageDigest

            if image_id:
                if re.match("^[\d|a-f]{64}$", image_id):
                    imageId = image_id
                else:
                    raise ValueError("input image_id does not validate")
            else:
                # TODO this could be improved to generate imageId from configuration hash
                imageId = "{}".format(
                    "".join([random.choice("0123456789abcdef") for x in range(0, 64)])
                )

            if account_id:
                userId = account_id
            else:
                userId = "admin"

            if created_at:
                if int(created_at) < 0 or int(created_at) > now + 1:
                    raise ValueError(
                        "created_at must by a unix timestamp between 0 and now ({})".format(
                            now
                        )
                    )
            else:
                created_at = now

            try:
                inputTag = tag
                image_info = parse_dockerimage_string(inputTag)
                if (
                    not inputTag.startswith("docker.io/")
                    and image_info.get("registry", "") == "docker.io"
                ):
                    # undo the auto-fill of 'docker.io' for input that doesn't specify registry
                    image_info["registry"] = "localbuild"
                fulltag = "{}/{}:{}".format(
                    image_info["registry"], image_info["repo"], image_info["tag"]
                )
                fulldigest = "{}/{}@{}".format(
                    image_info["registry"], image_info["repo"], imageDigest
                )
                logger.info(
                    "using fulltag={} fulldigest={}".format(fulltag, fulldigest)
                )
            except Exception as err:
                raise ValueError(
                    "input tag does not validate - exception: {}".format(err)
                )

            dockerfile_mode = "Guessed"
            dockerfile_contents = None
            if dockerfile:
                with open(dockerfile, "r") as FH:
                    dockerfile_contents = ensure_str(
                        base64.b64encode(ensure_bytes(FH.read()))
                    )
                    dockerfile_mode = "Actual"

            annotations = {}
            if annotation:
                for a in annotation:
                    try:
                        (k, v) = a.split("=", 1)
                        if k and v:
                            annotations[k] = v
                        else:
                            raise Exception("found null in key or value")
                    except Exception:
                        raise ValueError(
                            "annotation format error - annotations must be of the form (--annotation key=value), found: {}".format(
                                a
                            )
                        )

            workspace_root = config["tmp_dir"]
        except Exception as err:
            # input setup/validation failure
            raise err

        logger.debug(
            "input has been prepared: imageDigest={} parentDigest={} imageId={} inputTag={} fulltag={} fulldigest={} userId={} annotations={} created_at={}".format(
                imageDigest,
                parentDigest,
                imageId,
                inputTag,
                fulltag,
                fulldigest,
                userId,
                annotations,
                created_at,
            )
        )

        # create an image record
        try:
            image_record = make_image_record(
                userId,
                "docker",
                None,
                image_metadata={
                    "tag": fulltag,
                    "digest": fulldigest,
                    "imageId": imageId,
                    "parentdigest": parentDigest,
                    "created_at": created_at,
                    "dockerfile": dockerfile_contents,
                    "dockerfile_mode": dockerfile_mode,
                    "annotations": annotations,
                },
                registry_lookup=False,
                registry_creds=(None, None),
            )
            image_record["created_at"] = created_at
            image_record["last_updated"] = created_at
            image_record["analyzed_at"] = now
            image_record["analysis_status"] = "analyzed"
            image_record["image_status"] = "active"
            image_record["record_state_key"] = "active"
            for image_detail in image_record["image_detail"]:
                image_detail["created_at"] = created_at
                image_detail["last_updated"] = created_at
                image_detail["tag_detected_at"] = created_at
                image_detail["record_state_key"] = "active"
        except Exception as err:
            # image record setup fail
            raise err

        # perform analysis
        image_data, analyzed_manifest_data = analyze_image(
            userId,
            rawmanifest,
            image_record,
            workspace_root,
            config,
            registry_creds=[],
            use_cache_dir=None,
            image_source="docker-archive",
            image_source_meta=docker_archive,
        )

        image_content_data = {}
        for content_type in (
            anchore_engine.common.image_content_types
            + anchore_engine.common.image_metadata_types
        ):
            try:
                image_content_data[
                    content_type
                ] = anchore_engine.common.helpers.extract_analyzer_content(
                    image_data, content_type, manifest=input_manifest_data
                )
            except Exception:
                logger.exception(
                    "Unable to determine content_type, will fallback to {}"
                )
                image_content_data[content_type] = {}

        anchore_engine.common.helpers.update_image_record_with_analysis_data(
            image_record, image_data
        )
        image_record["image_size"] = int(image_record["image_size"])

        # generate an output image archive tarball
        archive_file = anchore_archive
        try:
            with ImageArchive.for_writing(archive_file) as img_archive:

                img_archive.account = userId
                img_archive.image_digest = imageDigest
                img_archive.manifest.metadata = {
                    "versions": localconfig.get_versions(),
                    "image_id": imageId,
                    "image_record": json.dumps(image_record, sort_keys=True),
                }

                pack_data = {"document": image_data}
                data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
                img_archive.add_artifact(
                    "analysis",
                    source=ObjectStoreLocation(bucket="analysis_data", key=imageDigest),
                    data=data,
                    metadata=None,
                )

                pack_data = {"document": image_content_data}
                data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
                img_archive.add_artifact(
                    "image_content",
                    source=ObjectStoreLocation(
                        bucket="image_content_data", key=imageDigest
                    ),
                    data=data,
                    metadata=None,
                )

                pack_data = {"document": input_manifest_data}
                data = ensure_bytes(json.dumps(pack_data, sort_keys=True))
                img_archive.add_artifact(
                    "image_manifest",
                    source=ObjectStoreLocation(bucket="manifest_data", key=imageDigest),
                    data=data,
                    metadata=None,
                )
        except Exception as err:
            # archive tarball generate fail
            raise err

    except Exception as err:
        log_error("db", err)
        fail_exit()

    click.echo(
        "Analysis complete for image {} - archive file is located at {}".format(
            imageDigest, archive_file
        )
    )
