from connexion import request

# anchore modules
import anchore_engine.apis
from anchore_engine.apis.authorization import get_authorizer

import anchore_engine.common.helpers
import anchore_engine.common
import anchore_engine.subsys.servicestatus
import anchore_engine.configuration.localconfig
from anchore_engine.db.entities.catalog import QueueItem

authorizer = get_authorizer()


@authorizer.requires([])
def get_webhook_schema():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = {}
    httpcode = 500
    try:
        return_object = QueueItem.to_schema()
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode
