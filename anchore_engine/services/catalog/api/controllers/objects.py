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
from anchore_engine.common.helpers import make_response_error
from anchore_engine.subsys.metrics import flask_metrics

authorizer = get_authorizer()


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_object(bucket, archiveid):
    httpcode = 500
    try:
        obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()
        account_name = ApiRequestContextProxy.namespace()
        try:
            return_object = json.loads(
                anchore_utils.ensure_str(obj_mgr.get(account_name, bucket, archiveid))
            )
            httpcode = 200
        except Exception as err:
            httpcode = 404
            raise err
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_object(bucket, archiveid, bodycontent):
    httpcode = 500
    try:
        account_name = ApiRequestContextProxy.namespace()
        obj_mgr = anchore_engine.subsys.object_store.manager.get_manager()

        jsonbytes = anchore_utils.ensure_bytes(json.dumps(bodycontent))
        rc = obj_mgr.put(account_name, bucket, archiveid, jsonbytes)

        my_svc = ApiRequestContextProxy.get_service()
        if my_svc is not None:
            resource_url = (
                my_svc.service_record["base_url"]
                + "/"
                + my_svc.service_record["version"]
                + "/archive/"
                + bucket
                + "/"
                + archiveid
            )
        else:
            resource_url = "N/A"

        return_object = resource_url
        httpcode = 200

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


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
