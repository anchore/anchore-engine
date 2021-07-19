import datetime
from hashlib import sha256

from connexion import request

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db import session_scope
from anchore_engine.db.entities.catalog import (
    ImageImportContent,
    ImageImportOperation,
    ImportState,
)
from anchore_engine.subsys import logger
from anchore_engine.subsys.object_store import manager
from anchore_engine.utils import datetime_to_rfc3339, ensure_str

authorizer = get_authorizer()

IMPORT_BUCKET = "image_content_imports"

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
OPERATION_EXPIRATION_DELTA = datetime.timedelta(hours=24)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_operation():
    """
    POST /imports/images

    :return:
    """
    try:
        with session_scope() as db_session:
            op = ImageImportOperation()
            op.account = ApiRequestContextProxy.namespace()
            op.status = ImportState.pending
            op.expires_at = datetime.datetime.utcnow() + OPERATION_EXPIRATION_DELTA

            db_session.add(op)
            db_session.flush()
            resp = op.to_json()

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_operations():
    """
    GET /imports/images

    :return:
    """
    try:
        with session_scope() as db_session:
            resp = [
                x.to_json()
                for x in db_session.query(ImageImportOperation)
                .filter_by(account=ApiRequestContextProxy.namespace())
                .all()
            ]

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_operation(operation_id):
    """
    GET /imports/images/{operation_id}

    :param operation_id:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def invalidate_operation(operation_id):
    """
    DELETE /imports/images/{operation_id}

    :param operation_id:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                if record.status not in [
                    ImportState.invalidated,
                    ImportState.complete,
                    ImportState.processing,
                ]:
                    record.status = ImportState.invalidated
                    db_session.flush()

                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_operation(operation_id, operation):
    """
    PUT /imports/images/{operation_id}

    Will only update the status, no other fields

    :param operation_id:
    :param operation: content of operation to update
    :return:
    """
    if not operation.get("status"):
        raise api_exceptions.BadRequest("status field required", detail={})

    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if record:
                if record.status.is_active():
                    record.status = ImportState(operation.get("status"))
                    db_session.flush()
                else:
                    raise api_exceptions.BadRequest(
                        "Cannot update status for import in terminal state",
                        detail={"status": record.status},
                    )
                resp = record.to_json()
            else:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

        return resp, 200
    except api_exceptions.AnchoreApiError as err:
        return (
            make_response_error(err, in_httpcode=err.__response_code__),
            err.__response_code__,
        )
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


def generate_import_bucket():
    return IMPORT_BUCKET


def generate_key(account, op_id, content_type, digest):
    return "{}/{}/{}/{}".format(account, op_id, content_type, digest)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_packages(operation_id):
    """
    POST /imports/images/{operation_id}/packages

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "packages", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_packages(operation_id: str):
    """
    GET /imports/images/{operations_id}/packages

    :param operation_id:
    :return:
    """

    return list_import_content(
        operation_id, ApiRequestContextProxy.namespace(), "packages"
    )


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_dockerfile(operation_id):
    """
    POST /imports/images/{operation_id}/dockerfile

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "dockerfile", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_dockerfiles(operation_id: str):
    """
    GET /imports/images/{operations_id}/dockerfile

    :param operation_id:
    :return:
    """
    return list_import_content(
        operation_id, ApiRequestContextProxy.namespace(), "dockerfile"
    )


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "manifest", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_manifests(operation_id: str):
    """
    GET /imports/images/{operations_id}/manifest

    :param operation_id:
    :return:
    """
    return list_import_content(
        operation_id, ApiRequestContextProxy.namespace(), "manifest"
    )


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_parent_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/parent_manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "parent_manifest", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_parent_manifests(operation_id: str):
    """
    GET /imports/images/{operations_id}/parent_manifest

    :param operation_id:
    :return:
    """
    return list_import_content(
        operation_id, ApiRequestContextProxy.namespace(), "parent_manifest"
    )


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_image_config(operation_id):
    """
    POST /imports/images/{operation_id}/image_config

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "image_config", request)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_import_image_configs(operation_id: str):
    """
    GET /imports/images/{operations_id}/image_config

    :param operation_id:
    :return:
    """
    return list_import_content(
        operation_id, ApiRequestContextProxy.namespace(), "image_config"
    )


def content_upload(operation_id, content_type, request):
    """
    Generic handler for multiple types of content uploads. Still operates at the API layer

    :param operation_id:
    :param content_type:
    :param request:
    :return:
    """
    try:
        with session_scope() as db_session:
            record = (
                db_session.query(ImageImportOperation)
                .filter_by(
                    account=ApiRequestContextProxy.namespace(), uuid=operation_id
                )
                .one_or_none()
            )
            if not record:
                raise api_exceptions.ResourceNotFound(resource=operation_id, detail={})

            if not record.status.is_active():
                raise api_exceptions.ConflictingRequest(
                    message="import operation status does not allow uploads",
                    detail={"status": record.status},
                )

            if not request.content_length:
                raise api_exceptions.BadRequest(
                    message="Request must contain content-length header", detail={}
                )
            elif request.content_length > MAX_UPLOAD_SIZE:
                raise api_exceptions.BadRequest(
                    message="too large. Max size of 100MB supported for content",
                    detail={"content-length": request.content_length},
                )

            digest, created_at = save_import_content(
                db_session, operation_id, request.data, content_type
            )

        resp = {"digest": digest, "created_at": datetime_to_rfc3339(created_at)}

        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


def save_import_content(
    db_session, operation_id: str, content: bytes, content_type: str
) -> tuple:
    """
    Generic handler for content type saving that does not do any validation.

    :param operation_id:
    :param sbom:
    :return:
    """
    hasher = sha256(content)  # Direct bytes hash
    digest = hasher.digest().hex()

    found_content = (
        db_session.query(ImageImportContent)
        .filter(
            ImageImportContent.operation_id == operation_id,
            ImageImportContent.content_type == content_type,
            ImageImportContent.digest == digest,
        )
        .one_or_none()
    )

    if found_content:
        logger.info("Found existing record {}".format(found_content.digest))
        # Short circuit since already present
        return found_content.digest, found_content.created_at

    import_bucket = generate_import_bucket()
    key = generate_key(
        ApiRequestContextProxy.namespace(), operation_id, content_type, digest
    )

    content_record = ImageImportContent()
    content_record.account = ApiRequestContextProxy.namespace()
    content_record.digest = digest
    content_record.content_type = content_type
    content_record.operation_id = operation_id
    content_record.content_storage_bucket = import_bucket
    content_record.content_storage_key = key

    db_session.add(content_record)
    db_session.flush()

    mgr = manager.object_store.get_manager()
    resp = mgr.put_document(
        ApiRequestContextProxy.namespace(), import_bucket, key, ensure_str(content)
    )
    if not resp:
        # Abort the transaction
        raise Exception("Could not save into object store")

    return digest, content_record.created_at


def list_import_content(operation_id: str, account: str, content_type: str):
    """
    Generic way to list content of a given type from the db entries

    :param operation_id:
    :param account:
    :param content_type:
    :return:
    """
    try:
        with session_scope() as db_session:
            resp = []
            for x in (
                db_session.query(ImageImportContent)
                .join(ImageImportContent.operation)
                .filter(
                    ImageImportOperation.account == account,
                    ImageImportOperation.uuid == operation_id,
                    ImageImportContent.content_type == content_type,
                )
            ):
                resp.append(
                    {
                        "created_at": datetime_to_rfc3339(x.created_at),
                        "digest": x.digest,
                    }
                )

        return resp, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500
