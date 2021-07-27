"""
Controller for object storage apis. Formerly known as 'data_archive.py' and formerly the document archive, now renamed since there
is an actual archive system distinct from object storage.

Simple get/post/delete api for unstructured data and json data storage
"""

import json

import anchore_engine.apis
import anchore_engine.services
import anchore_engine.subsys.object_store.manager
from anchore_engine import utils as anchore_utils
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.subsys.metrics import flask_metrics

authorizer = get_authorizer()


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_object(bucket, archiveid):
    return_object, httpcode = get_object_from_storage(bucket, archiveid, is_json=True)
    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_object(bucket, archiveid, bodycontent):
    return_object, http_code = create_object_in_storage(
        bucket, archiveid, bodycontent, is_json=True
    )
    return return_object, http_code


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_object(bucket, archiveid):
    httpcode = 500
    try:
        obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()
        account_name = ApiRequestContextProxy.namespace()
        rc = obj_mgr.delete(account_name, bucket, archiveid)
        httpcode = 200
        return_object = None
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_raw_object(bucket, archiveid, bodycontent):
    return_object, http_code = create_object_in_storage(
        bucket, archiveid, bodycontent, is_json=False
    )
    return return_object, http_code


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_raw_object(bucket, archiveid):
    return_object, httpcode = get_object_from_storage(bucket, archiveid, is_json=False)
    return return_object, httpcode


def create_object_in_storage(
    bucket: str, archiveid: str, bodycontent: str, is_json: bool = False
):
    """
    Creates an object in storeage with the object storage manager.
    Takes param to determine if it should be stored as json or not.
    Used by two endpoints so that a single endpoint does not return multiple different content types
    """
    http_code = 500
    try:
        account_name = ApiRequestContextProxy.namespace()
        obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()

        if is_json:
            bodycontent = anchore_utils.ensure_bytes(json.dumps(bodycontent))

        obj_mgr.put(account_name, bucket, archiveid, bodycontent)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=http_code
        )
        return return_object, http_code

    my_svc = ApiRequestContextProxy.get_service()
    if my_svc is None:
        resource_url = "N/A"
    else:
        try:
            path_parts = [
                my_svc.service_record["base_url"],
                my_svc.service_record["version"],
                "archive",
                bucket,
                archiveid,
            ]
        except KeyError as err:
            return_object = anchore_engine.common.helpers.make_response_error(
                err, in_httpcode=http_code
            )
            return return_object, http_code
        resource_url = "/".join(path_parts)
    return_object = resource_url
    http_code = 200
    return return_object, http_code


def get_object_from_storage(bucket: str, archiveid: str, is_json: bool = False):
    """
    Gets an object from object storage
    Has condition to return it as json or not
    This is used by two endpoints so that a single endpoint does not return multiple different content types
    """
    http_code = 200
    try:
        obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()
        account_name = ApiRequestContextProxy.namespace()
        return_object = obj_mgr.get(account_name, bucket, archiveid)

        if not return_object:
            http_code = 404
            return_object = anchore_engine.common.helpers.make_response_error(
                "No document found at given path", in_httpcode=http_code
            )
        elif is_json:
            return_object = json.loads(return_object)

    except Exception as err:
        http_code = 500
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=http_code
        )
    return return_object, http_code
