"""
Archive controller is a new controller for managing archive storage. This is a new (as of v0.4.0) class of storage
in the engine. The old 'archive' system is now call the 'object store' and uses the '/objects' route prefix (see objects.py).


"""

import json

import anchore_engine.apis
import anchore_engine.services
from anchore_engine import db
from anchore_engine import utils as anchore_utils
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.subsys import archive
from anchore_engine.subsys.metrics import flask_metrics

authorizer = get_authorizer()


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_archive(bucket, archiveid):
    httpcode = 500

    try:
        archive_sys = archive.get_manager()
        accountName = ApiRequestContextProxy.namespace()

        try:
            return_object = json.loads(
                anchore_utils.ensure_str(
                    archive_sys.get(accountName, bucket, archiveid)
                )
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
def create_archive(bucket, archiveid, bodycontent):
    httpcode = 500
    try:
        accountName = ApiRequestContextProxy.namespace()
        archive_sys = archive.get_manager()

        try:
            jsonbytes = anchore_utils.ensure_bytes(json.dumps(bodycontent))
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

            rc = archive_sys.put(accountName, bucket, archiveid, jsonbytes)
            return_object = resource_url
            httpcode = 200
        except Exception as err:
            httpcode = 500
            raise err

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_archive(bucket, archiveid):
    httpcode = 500
    try:
        archive_sys = archive.get_manager()
        account_name = ApiRequestContextProxy.namespace()
        with db.session_scope() as session:
            rc = archive_sys.delete(account_name, bucket, archiveid)
            httpcode = 200
            return_object = None
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode
