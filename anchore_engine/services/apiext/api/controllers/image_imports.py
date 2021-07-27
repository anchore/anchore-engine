import datetime

from connexion import request

from anchore_engine.apis import exceptions as api_exceptions
from anchore_engine.apis.authorization import (
    ActionBoundPermission,
    RequestingAccountValue,
    get_authorizer,
)
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.subsys import logger

authorizer = get_authorizer()

IMPORT_BUCKET = "image_content_imports"

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
OPERATION_EXPIRATION_DELTA = datetime.timedelta(hours=24)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def create_operation():
    """
    POST /imports/images

    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.create_image_import()
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_operations():
    """
    GET /imports/images

    :return:
    """

    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_image_import_operations()
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_operation(operation_id):
    """
    GET /imports/images/{operation_id}

    :param operation_id:
    :return:
    """

    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.get_image_import_operation(operation_id)
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def invalidate_operation(operation_id):
    """
    DELETE /imports/images/{operation_id}

    :param operation_id:
    :return:
    """

    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.cancel_image_import(operation_id)
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_import_packages(operation_id):
    """
    GET /imports/images/{operation_id}/packages

    :param operation_id:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_import_content(operation_id, "packages")
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_import_dockerfiles(operation_id):
    """
    GET /imports/images/{operation_id}/dockerfile

    :param operation_id:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_import_content(operation_id, "dockerfile")
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_import_image_manifests(operation_id):
    """
    GET /imports/images/{operation_id}/manifest

    :param operation_id:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_import_content(operation_id, "manifest")
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_import_parent_manifests(operation_id):
    """
    GET /imports/images/{operation_id}/manifest

    :param operation_id:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_import_content(operation_id, "parent_manifest")
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_import_image_configs(operation_id):
    """
    GET /imports/images/{operation_id}/image_config

    :param operation_id:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        resp = client.list_import_content(operation_id, "image_config")
        return resp, 200
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_packages(operation_id):
    """
    POST /imports/images/{operation_id}/packages

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "packages", request)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_dockerfile(operation_id):
    """
    POST /imports/images/{operation_id}/dockerfile

    :param operation_id:
    :param sbom:
    :return:
    """

    return content_upload(operation_id, "dockerfile", request)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "manifest", request)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_parent_manifest(operation_id):
    """
    POST /imports/images/{operation_id}/parent_manifest

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "parent_manifest", request)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def import_image_config(operation_id):
    """
    POST /imports/images/{operation_id}/image_config

    :param operation_id:
    :return:
    """

    return content_upload(operation_id, "image_config", request)


def content_upload(operation_id, content_type, request):
    """
    Generic handler for multiple types of content uploads. Still operates at the API layer

    :param operation_id:
    :param content_type:
    :param request:
    :return:
    """
    try:
        client = internal_client_for(
            CatalogClient, userId=ApiRequestContextProxy.namespace()
        )
        return (
            client.upload_image_import_content(
                operation_id, content_type, request.data
            ),
            200,
        )
    except api_exceptions.AnchoreApiError as ex:
        return (
            make_response_error(ex, in_httpcode=ex.__response_code__),
            ex.__response_code__,
        )
    except Exception as ex:
        logger.exception("Unexpected error in api processing")
        return make_response_error(ex, in_httpcode=500), 500
