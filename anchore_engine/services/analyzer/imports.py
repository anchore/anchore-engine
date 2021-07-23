import json
import time

import anchore_engine.clients.localanchore_standalone
from anchore_engine.analyzers.syft import convert_syft_to_engine
from anchore_engine.analyzers.utils import merge_nested_dict
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.models.schemas import (
    ImportQueueMessage,
    InternalImportManifest,
    ValidationError,
)
from anchore_engine.configuration import localconfig
from anchore_engine.services.analyzer.analysis import (
    ANALYSIS_TIME_SECONDS_BUCKETS as IMPORT_TIME_SECONDS_BUCKETS,
)
from anchore_engine.services.analyzer.analysis import (
    analysis_failed_metrics,
    notify_analysis_complete,
    store_analysis_results,
)
from anchore_engine.services.analyzer.utils import (
    emit_events,
    update_analysis_complete,
    update_analysis_failed,
    update_analysis_started,
)
from anchore_engine.subsys import events, logger, metrics, taskstate
from anchore_engine.util.docker import (
    DockerV1ManifestMetadata,
    DockerV2ManifestMetadata,
)
from anchore_engine.utils import AnchoreException

from .tasks import WorkerTask


class InvalidImageStateException(Exception):
    pass


class MissingRequiredContentException(Exception):
    pass


REQUIRED_CONTENT_TYPES = ["packages", "manifest", "image_config"]
JSON_CONTENT_TYPES = [
    "manifest",
    "parent_manifest",
    "image_config",
    "packages",
]


def get_image_size(manifest: dict):
    """
    Sum the layer sizes from the manifest to get an image size
    :param manifest:
    :return:
    """

    return sum([x.get("size", 0) for x in manifest.get("layers", [])])


# Copied and modified from the localanchore_standalone file's analyze_image()
def process_import(
    image_record: dict,
    sbom: dict,
    import_manifest: InternalImportManifest,
    enable_package_filtering=True,
):
    """

    :param image_record:
    :param sbom: map of content type to manifest (e.g. {'packages': {....}, 'dockerfile': '....'}
    :param import_manifest:
    :return:
    """

    # need all this
    analyzer_manifest = {}
    image_id = import_manifest.local_image_id or import_manifest.digest
    syft_packages = sbom.get("packages")
    dockerfile = sbom.get("dockerfile")
    manifest = sbom.get("manifest")
    image_config = sbom.get("image_config")

    if manifest.get("schemaVersion", 1) == 2:
        parser = DockerV2ManifestMetadata(manifest, image_config)
    else:
        parser = DockerV1ManifestMetadata(manifest)

    layers = parser.layer_ids
    image_arch = parser.architecture
    docker_history = parser.history
    image_size = get_image_size(manifest)
    familytree = []

    pullstring = None
    fulltag = None
    if dockerfile:
        dockerfile_mode = "Actual"
    else:
        dockerfile_mode = "Guessed"
        dockerfile = parser.inferred_dockerfile

    try:
        image_digest = image_record["imageDigest"]
        if image_digest != import_manifest.digest:
            raise Exception(
                "Image digest in import manifest does not match catalog record"
            )

        image_detail = image_record["image_detail"][0]
        pullstring = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + "@"
            + image_detail["imageDigest"]
        )
        fulltag = (
            image_detail["registry"]
            + "/"
            + image_detail["repo"]
            + ":"
            + image_detail["tag"]
        )

        timer = time.time()

        distro = syft_packages.get("distro", {}).get("name")
        # Map 'redhat' distro to 'rhel' distro for consistency between internal metadata fetch from squashtar and the syft implementation used for import
        if distro == "redhat":
            distro = "rhel"

        # Move data from the syft sbom into the analyzer output
        analyzer_report = {
            "analyzer_meta": {
                "analyzer_meta": {
                    "base": {
                        "DISTRO": distro,
                        "DISTROVERS": syft_packages.get("distro", {}).get("version"),
                        "LIKEDISTRO": syft_packages.get("distro", {}).get("idLike"),
                    }
                }
            }
        }

        try:
            syft_results = convert_syft_to_engine(
                syft_packages, enable_package_filtering=enable_package_filtering
            )
            merge_nested_dict(analyzer_report, syft_results)
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalysisError(
                cause=err, pull_string=pullstring, tag=fulltag
            )
        logger.debug(
            "timing: total analyzer time: {} - {}".format(
                pullstring, time.time() - timer
            )
        )

        try:
            image_report = (
                anchore_engine.clients.localanchore_standalone.generate_image_export(
                    image_id,
                    analyzer_report,
                    image_size,
                    fulltag,
                    docker_history,
                    dockerfile_mode,
                    dockerfile,
                    layers,
                    familytree,
                    image_arch,
                    pullstring,
                    analyzer_manifest,
                )
            )
        except Exception as err:
            raise anchore_engine.clients.localanchore_standalone.AnalysisReportGenerationError(
                cause=err, pull_string=pullstring, tag=fulltag
            )

    except AnchoreException:
        raise
    except Exception as err:
        raise anchore_engine.clients.localanchore_standalone.AnalysisError(
            cause=err,
            pull_string=pullstring,
            tag=fulltag,
            msg="failed to download, unpack, analyze, and generate image export",
        )

    # if not imageDigest or not imageId or not manifest or not image_report:
    if not image_report:
        raise Exception("failed to analyze")

    return [image_report, manifest]


def get_content(
    manifest: InternalImportManifest,
    client: CatalogClient,
) -> dict:

    content_map = {}
    for content_ref in manifest.contents:
        logger.info(
            "loading import content type %s from %s/%s",
            content_ref.content_type,
            content_ref.bucket,
            content_ref.key,
        )
        raw = client.get_document(content_ref.bucket, content_ref.key)
        if content_ref.content_type in JSON_CONTENT_TYPES:
            content_map[content_ref.content_type] = json.loads(raw)
        else:
            content_map[content_ref.content_type] = raw

    return content_map


def check_required_content(sbom_map: dict):
    for x in REQUIRED_CONTENT_TYPES:
        if not sbom_map.get(x):
            raise MissingRequiredContentException(
                "Required content type {} not loaded".format(x)
            )


def import_image(
    operation_id,
    account,
    import_manifest: InternalImportManifest,
    enable_package_filtering=True,
):
    """
    The main thread of exec for importing an image

    :param operation_id:
    :param account:
    :param import_manifest:
    :return:
    """
    timer = int(time.time())
    analysis_events = []

    config = localconfig.get_config()
    all_content_types = config.get("image_content_types", []) + config.get(
        "image_metadata_types", []
    )
    image_digest = import_manifest.digest

    try:
        catalog_client = internal_client_for(CatalogClient, account)

        # check to make sure image is still in DB
        catalog_client = internal_client_for(CatalogClient, account)
        try:
            image_record = catalog_client.get_image(image_digest)
            if not image_record:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.debug_exception("Could not get image record")
            logger.warn(
                "dequeued image cannot be fetched from catalog - skipping analysis ("
                + str(image_digest)
                + ") - exception: "
                + str(err)
            )
            return True

        if image_record["analysis_status"] != taskstate.base_state("analyze"):
            logger.info(
                "dequeued image to import is not in base 'not_analyzed' state - skipping import"
            )
            return True

        try:
            last_analysis_status = image_record["analysis_status"]
            image_record = update_analysis_started(
                catalog_client, image_digest, image_record
            )

            logger.info("Loading content from import")
            sbom_map = get_content(import_manifest, catalog_client)

            manifest = sbom_map.get("manifest")

            try:
                logger.info("processing image import data")
                image_data, analysis_manifest = process_import(
                    image_record, sbom_map, import_manifest, enable_package_filtering
                )
            except AnchoreException as e:
                event = events.ImageAnalysisFailed(
                    user_id=account, image_digest=image_digest, error=e.to_dict()
                )
                analysis_events.append(event)
                raise

            # Store the manifest in the object store
            logger.info("storing image manifest")
            catalog_client.put_document(
                bucket="manifest_data", name=image_digest, inobj=json.dumps(manifest)
            )

            # Save the results to the upstream components and data stores
            logger.info("storing import result")
            store_analysis_results(
                account,
                image_digest,
                image_record,
                image_data,
                manifest,
                analysis_events,
                all_content_types,
            )

            logger.info("updating image catalog record analysis_status")
            last_analysis_status = image_record["analysis_status"]
            image_record = update_analysis_complete(
                catalog_client, image_digest, image_record
            )
            try:
                analysis_events.extend(
                    notify_analysis_complete(image_record, last_analysis_status)
                )
            except Exception as err:
                logger.warn(
                    "failed to enqueue notification on image analysis state update - exception: "
                    + str(err)
                )

            logger.info(
                "analysis complete: " + str(account) + " : " + str(image_digest)
            )

            try:
                catalog_client.update_image_import_status(
                    operation_id, status="complete"
                )
            except Exception as err:
                logger.debug_exception(
                    "failed updating import status success, will continue and rely on expiration for GC later"
                )

            try:
                metrics.counter_inc(name="anchore_import_success")
                run_time = float(time.time() - timer)

                metrics.histogram_observe(
                    "anchore_import_time_seconds",
                    run_time,
                    buckets=IMPORT_TIME_SECONDS_BUCKETS,
                    status="success",
                )

            except Exception as err:
                logger.warn(str(err))

        except Exception as err:
            run_time = float(time.time() - timer)
            logger.exception("problem importing image - exception: " + str(err))
            analysis_failed_metrics(run_time)

            # Transition the image record to failure status
            image_record = update_analysis_failed(
                catalog_client, image_digest, image_record
            )

            try:
                catalog_client.update_image_import_status(operation_id, status="failed")
            except Exception as err:
                logger.debug_exception(
                    "failed updating import status failure, will continue and rely on expiration for GC later"
                )

            if account and image_digest:
                for image_detail in image_record["image_detail"]:
                    fulltag = (
                        image_detail["registry"]
                        + "/"
                        + image_detail["repo"]
                        + ":"
                        + image_detail["tag"]
                    )
                    event = events.UserAnalyzeImageFailed(
                        user_id=account, full_tag=fulltag, error=str(err)
                    )
                    analysis_events.append(event)
        finally:
            if analysis_events:
                emit_events(catalog_client, analysis_events)

    except Exception as err:
        logger.debug_exception("Could not import image")
        logger.warn("job processing bailed - exception: " + str(err))
        raise err

    return True


class ImportTask(WorkerTask):
    """
    The task to import an analysis performed externally
    """

    def __init__(
        self, message: ImportQueueMessage, owned_package_filtering_enabled: bool
    ):
        super().__init__()
        self.message = message
        self.account = message.account
        self.owned_package_filtering_enabled = owned_package_filtering_enabled

    def execute(self):
        logger.info(
            "Executing import task. Account = %s, Id = %s", self.account, self.task_id
        )

        import_image(
            self.message.manifest.operation_uuid,
            self.account,
            self.message.manifest,
            enable_package_filtering=self.owned_package_filtering_enabled,
        )
        logger.info("Import task %s complete", self.task_id)


def is_import_message(payload_json: dict) -> bool:
    try:
        return ImportQueueMessage.from_json(payload_json) is not None
    except ValidationError:
        return False
