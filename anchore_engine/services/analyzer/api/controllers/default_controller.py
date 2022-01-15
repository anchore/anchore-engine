from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.subsys import servicestatus

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def status():
    httpcode = 500
    try:
        service_record = servicestatus.get_my_service_record()
        return_object = servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode
