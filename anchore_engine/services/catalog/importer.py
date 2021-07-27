import enum

import retrying

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.models.schemas import (
    ImportContentReference,
    ImportManifest,
    ImportQueueMessage,
    InternalImportManifest,
)
from anchore_engine.db import ImageImportContent, ImageImportOperation, db_catalog_image
from anchore_engine.db.entities.catalog import ImportState
from anchore_engine.services.catalog.catalog_impl import add_or_update_image
from anchore_engine.subsys import logger, taskstate
from anchore_engine.subsys.object_store import get_manager
from anchore_engine.util.docker import DockerImageReference

IMPORT_QUEUE = "images_to_analyze"
ANCHORE_SYSTEM_ANNOTATION_KEY_PREFIX = "anchore.system/"
IMPORT_OPERATION_ANNOTATION_KEY = (
    ANCHORE_SYSTEM_ANNOTATION_KEY_PREFIX + "import_operation_id"
)


class ImportTypes(enum.Enum):
    """
    The types of content supported for upload
    """

    packages = "packages"
    dockerfile = "dockerfile"
    manifest = "manifest"
    parent_manifest = "parent_manifest"
    image_config = "image_config"


# Types that must be presnt in an import manifest for the system to begin the import process
REQUIRED_IMPORT_TYPES = [
    ImportTypes.packages,
    ImportTypes.manifest,
    ImportTypes.image_config,
]


@retrying.retry(wait_fixed=1000, stop_max_attempt_number=3)
def queue_import_task(
    account: str, operation_id: str, manifest: InternalImportManifest
) -> bool:
    """
    Queue the task for analysis

    :param account:
    :param manifest:
    :return:
    """
    # Replace this is a state watcher, similar to the image state handlers
    logger.debug(
        "Queueing import task for account %s operation id %s", account, operation_id
    )

    task = ImportQueueMessage()
    task.account = account
    task.manifest = manifest
    task.operation_uuid = operation_id
    task.image_digest = manifest.digest

    q_client = internal_client_for(SimpleQueueClient, userId=account)
    resp = q_client.enqueue(name=IMPORT_QUEUE, inobj=task.to_json())
    logger.debug("Queue task response: %s", str(resp))
    return True


def verify_import_manifest_content(
    db_session, operation_id: str, import_manifest: ImportManifest
):
    """
    Verify the content of the manifest and return a list of any content digests referenced in the manifest but not found in the system
    :param operation_id:
    :param import_manifest:
    :param db_session:
    :return: set of missing content digests
    """

    records = []
    if import_manifest.contents.packages:
        found = (
            db_session.query(ImageImportContent)
            .filter(
                ImageImportContent.operation_id == operation_id,
                ImageImportContent.digest == import_manifest.contents.packages,
                ImageImportContent.content_type == ImportTypes.packages.value,
            )
            .one_or_none()
        )

        if found is None:
            raise ValueError(import_manifest.contents.packages)

        records.append(found)

    if import_manifest.contents.dockerfile:
        found = (
            db_session.query(ImageImportContent)
            .filter(
                ImageImportContent.operation_id == operation_id,
                ImageImportContent.digest == import_manifest.contents.dockerfile,
                ImageImportContent.content_type == ImportTypes.dockerfile.value,
            )
            .one_or_none()
        )

        if found is None:
            raise ValueError(import_manifest.contents.dockerfile)
        records.append(found)

    if import_manifest.contents.manifest:
        found = (
            db_session.query(ImageImportContent)
            .filter(
                ImageImportContent.operation_id == operation_id,
                ImageImportContent.digest == import_manifest.contents.manifest,
                ImageImportContent.content_type == ImportTypes.manifest.value,
            )
            .one_or_none()
        )
        if found is None:
            raise ValueError(import_manifest.contents.manifest)
        records.append(found)

    if import_manifest.contents.parent_manifest:
        found = (
            db_session.query(ImageImportContent)
            .filter(
                ImageImportContent.operation_id == operation_id,
                ImageImportContent.digest == import_manifest.contents.parent_manifest,
                ImageImportContent.content_type == ImportTypes.parent_manifest.value,
            )
            .one_or_none()
        )
        if found is None:
            raise ValueError(import_manifest.contents.parent_manifest)
        records.append(found)

    if import_manifest.contents.image_config:
        found = (
            db_session.query(ImageImportContent)
            .filter(
                ImageImportContent.operation_id == operation_id,
                ImageImportContent.digest == import_manifest.contents.image_config,
                ImageImportContent.content_type == ImportTypes.image_config.value,
            )
            .one_or_none()
        )
        if found is None:
            raise ValueError(import_manifest.contents.parent_manifest)
        records.append(found)

    return records


def check_required_content(import_manifest: ImportManifest):
    """
    Verify that required fields are set

    :param import_manifest:
    :return:
    """
    for t in REQUIRED_IMPORT_TYPES:
        if getattr(import_manifest.contents, t.value) is None:
            raise api_exceptions.BadRequest(
                "import manifest must have digest for content type {} present", t.value
            )


def finalize_import_operation(
    db_session,
    account: str,
    operation_id: str,
    import_manifest: ImportManifest,
    final_state: ImportState = ImportState.processing,
) -> InternalImportManifest:
    """
    Finalize the import operation itself

    :param db_session:
    :param account:
    :param operation_id:
    :param import_manifest:
    :return:
    """
    record = (
        db_session.query(ImageImportOperation)
        .filter_by(account=account, uuid=operation_id)
        .one_or_none()
    )
    if not record:
        raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

    if record.status != ImportState.pending:
        raise api_exceptions.ConflictingRequest(
            message="Invalid operation status. Must be in pending state to finalize",
            detail={"status": record.status.value},
        )

    check_required_content(import_manifest)

    try:
        content_records = verify_import_manifest_content(
            db_session, operation_id, import_manifest
        )
    except ValueError as ex:
        raise api_exceptions.BadRequest(
            message="One or more referenced content digests not found for the operation id",
            detail={"digest": ex.args[0]},
        )

    try:
        internal_manifest = internal_manifest_from_external(
            import_manifest, content_records
        )

        # Update the status
        record.status = final_state
        # Queue presence should be gated by the image record, not here
        # queue_import_task(account, operation_id, internal_manifest)
    except:
        logger.debug_exception("Failed to queue task message. Setting failed status")
        record.status = ImportState.failed
        raise

    db_session.flush()

    return internal_manifest


def internal_manifest_from_external(
    manifest: ImportManifest, content_records: list
) -> InternalImportManifest:
    """
    Construct an internal manifest from an external one plus the db records for the content

    :param manifest: ImportManifest object
    :param content_records: list of ImageImportContent records
    :return:
    """
    internal_manifest = InternalImportManifest()
    internal_manifest.tags = manifest.tags
    internal_manifest.digest = manifest.digest
    internal_manifest.local_image_id = manifest.local_image_id
    internal_manifest.operation_uuid = manifest.operation_uuid
    internal_manifest.parent_digest = manifest.parent_digest

    internal_manifest.contents = []

    for record in content_records:
        ref = ImportContentReference()
        ref.digest = record.digest
        ref.content_type = record.content_type
        ref.bucket = record.content_storage_bucket
        ref.key = record.content_storage_key
        internal_manifest.contents.append(ref)

    return internal_manifest


def import_image(
    dbsession,
    account: str,
    operation_id: str,
    import_manifest: ImportManifest,
    force: bool = False,
    annotations: dict = None,
) -> dict:
    """
    Process the image import finalization, creating the new 'image' record and setting the proper state for queueing

    :param dbsession:
    :param account:
    :param operation_id:
    :param import_manifest:
    :param force:
    :param annotations:
    :return:
    """

    logger.debug(
        "Processing import image request with source operation_id = %s, annotations = %s",
        operation_id,
        annotations,
    )

    # Add annotation indicating this is an import
    annotations = add_import_annotations(import_manifest, annotations)

    # Import analysis for a new digest, or re-load analysis for existing image
    logger.debug("Loading image info using import operation id %s", operation_id)
    image_references = []
    for t in import_manifest.tags:
        r = DockerImageReference.from_string(t)
        r.digest = import_manifest.digest

        if import_manifest.local_image_id:
            r.image_id = import_manifest.local_image_id
        else:
            r.image_id = import_manifest.digest

        image_references.append(r)

    if not (image_references and image_references[0].has_digest()):
        raise ValueError("Must have image digest in image reference")

    # Check for dockerfile updates to an existing image
    found_img = db_catalog_image.get(
        imageDigest=import_manifest.digest, userId=account, session=dbsession
    )

    # Removed this to align processing with how analysis works: the status is updated *after* the add call
    # if the record already had an older status it will get reset
    if (
        found_img
        and found_img["analysis_status"] not in taskstate.fault_state("analyze")
        and not force
    ):
        # Load the existing manifest since we aren't going to use the import manifest for analysis
        obj_mgr = get_manager()
        manifest = obj_mgr.get_document(
            account, "manifest_data", found_img["imageDigest"]
        )
        parent_manifest = obj_mgr.get_document(
            account, "parent_manifest_data", found_img["imageDigest"]
        )

        # Don't allow a dockerfile update via import path
        dockerfile_content = None
        dockerfile_mode = None

        # Finalize the import, go straight to complete
        finalize_import_operation(
            dbsession,
            account,
            operation_id,
            import_manifest,
            final_state=ImportState.complete,
        )

        # raise BadRequest(
        #     "Cannot reload image that already exists unless using force=True for re-analysis",
        #     detail={"digest": import_manifest.digest},
        # )
    else:
        # Finalize the import
        internal_import_manifest = finalize_import_operation(
            dbsession, account, operation_id, import_manifest
        )

        # Get the dockerfile content if available
        if import_manifest.contents.dockerfile:
            rec = [
                ref
                for ref in internal_import_manifest.contents
                if ref.content_type == ImportTypes.dockerfile.value
            ][0]
            obj_mgr = get_manager()
            dockerfile_content = obj_mgr.get_document(
                userId=account,
                bucket=rec.bucket,
                archiveId=rec.key,
            )
            dockerfile_mode = "Actual"
        else:
            dockerfile_content = ""
            dockerfile_mode = "Guessed"

        # Set the manifest to the import manifest. This is swapped out for the real manifest during the import operation on
        # the analyzer
        manifest = internal_import_manifest.to_json()

        parent_manifest = ""

    # Update the db for the image record
    image_records = add_or_update_image(
        dbsession,
        account,
        image_references[0].image_id,
        tags=[x.tag_pullstring() for x in image_references],
        digests=[x.digest_pullstring() for x in image_references],
        parentdigest=import_manifest.parent_digest
        if import_manifest.parent_digest
        else import_manifest.digest,
        dockerfile=dockerfile_content,
        dockerfile_mode=dockerfile_mode,
        manifest=manifest,  # Fo now use the import manifest as the image manifest. This will get set to the actual manifest on the analyzer
        parent_manifest=parent_manifest,
        annotations=annotations,
    )
    if image_records:
        image_record = image_records[0]
    else:
        raise Exception("No record updated/inserted")

    return image_record


def add_import_annotations(import_manifest: ImportManifest, annotations: dict = None):
    """
    Add annotations to the image to correlate it with the operation_id it's created from

    :param import_manifest:
    :param annotations:
    :return: dict with merged annotations to track import
    """

    if not annotations:
        annotations = {}

    annotations[IMPORT_OPERATION_ANNOTATION_KEY] = import_manifest.operation_uuid
    return annotations
