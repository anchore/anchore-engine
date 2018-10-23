import connexion

import anchore_engine.apis
import anchore_engine.common.helpers
from anchore_engine import common
from anchore_engine.subsys import simplequeue, locking
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine.subsys import logger
import time
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED


authorizer = get_authorizer()

def normalize_errors(f):
    def decorator(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as err:
            logger.exception('API Error for {}'.format(f.__name__))
            resp = anchore_engine.common.helpers.make_response_error(err, in_httpcode=500)
            return resp, resp['httpcode']
    return decorator

@normalize_errors
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def status():
    logger.info('Hitting status!')
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    return_object = {}
    httpcode = 500

    #try:

    service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
    return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
    httpcode = 200

    # except Exception as err:
    #     return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
    #     httpcode = return_object['httpcode']

    logger.info('Exiting: {} {}'.format(return_object, httpcode))
    return return_object, httpcode

@normalize_errors
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def is_inqueue(queuename, bodycontent):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
    try:
        return_object = simplequeue.is_inqueue(queuename, bodycontent)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def qlen(queuename):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
    try:
        qlen = simplequeue.qlen(queuename)
        return_object = str(qlen)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def enqueue(queuename, bodycontent, forcefirst=None, qcount=0):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'forcefirst': forcefirst, 'qcount': qcount})
    try:
        return_object = simplequeue.enqueue(queuename, bodycontent, qcount=qcount, forcefirst=forcefirst)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def dequeue(queuename, wait_max_seconds=0, visibility_timeout=0):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    wait_expired = False
    wait_intervals = wait_max_seconds * 2
    return_object = None

    while not wait_expired:
        try:
            return_object = simplequeue.dequeue(queuename, visibility_timeout=visibility_timeout)
            if return_object:
                return (return_object, 200)
            else:

                # A very rough way to do long-polling, but occupies a thread during the wait
                if wait_intervals > 0:
                    wait_intervals -= 1
                    time.sleep(0.5)
                else:
                    wait_expired = True
        except Exception as err:
            return_object = str(err)
            return (return_object, 500)

    return (return_object, 200)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_message(queuename, receipt_handle):
    """
    Delete a message in given queue using the given receipt_handle, which must match the currently outstanding handle for the message.

    :param queuename:
    :param receipt_handle:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
    return_object = None
    try:
        if simplequeue.delete_msg(queuename, receipt_handle):
            httpcode = 200
        else:
            httpcode = 404
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_message_visibility_timeout(queuename, receipt_handle, visibility_timeout):
    """
    Delete a message in given queue using the given receipt_handle, which must match the currently outstanding handle for the message.

    :param queuename:
    :param receipt_handle:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
    try:
        result = simplequeue.update_visibility_timeout(queuename, receipt_handle, visibility_timeout)
        if result:
            return_object = result
            httpcode = 200
        else:
            httpcode = 400
            return_object = None
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def queues():
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = simplequeue.get_queuenames()
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_lease(lease_id):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().init_lease(lease_id)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_leases():
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().list()
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def describe_lease(lease_id):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().get(lease_id)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def acquire_lease(lease_id, client_id, ttl):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().acquire_lease(lease_id, client_id, ttl)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def release_lease(lease_id, client_id, epoch):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().release_lease(lease_id, client_id, epoch)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def refresh_lease(lease_id, client_id, ttl, epoch):
    request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

    try:
        return_object = locking.manager().refresh(lease_id, client_id, epoch, ttl)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return (return_object, httpcode)
