from connexion import request


# anchore modules
from anchore_engine.clients import catalog, simplequeue
import anchore_engine.services.common
from anchore_engine.subsys import logger
from anchore_engine.services.common import apiext_status

def make_response_service(user_auth, service_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in ['hostid', 'version', 'base_url', 'status_message', 'servicename']:
            ret[k] = service_record[k]
    except Exception as err:
        raise Exception("failed to format service response: " + str(err))

    # global items to filter out
    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)


def ping():
    """
    GET /

    :return: 200 status with no content
    """
    return

def get_service_detail():
    global apiext_status
    """
    GET /status

    :return: list of service details
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    httpcode = 500

    service_detail = {}
    return_object = {
        'busy':False,
        'up':True,
        'message': 'all good'
    }
    try:
        try:
            try:
                service_detail['service_states'] = []
                try:
                    up_services = {}
                    service_records = catalog.get_service(user_auth)
                    for service in service_records:
                        el = {}
                        for k in ['hostid', 'servicename', 'base_url', 'status', 'status_message']:
                            el[k] = service[k]
                        service_detail['service_states'].append(el)

                        if el['servicename'] not in up_services:
                            up_services[el['servicename']] = 0

                        if el['status']:
                            up_services[el['servicename']] += 1

                except Exception as err:
                    pass

                service_detail['queues'] = {}
                ret_queues = {}
                try:
                    queues = simplequeue.get_queues(user_auth)
                    for queuename in queues:
                        ret_queues[queuename] = {}
                        qlen = simplequeue.qlen(user_auth, queuename)
                        ret_queues[queuename]['qlen'] = qlen
                    service_detail['queues'] = ret_queues
                except:
                    pass

                service_detail['error_event'] = []
                try:
                    events = catalog.get_event(user_auth)
                    for event in events:
                        el = {}
                        for k in ['message_ts', 'hostId', 'message', 'level']:
                            el[k] = event[k]
                        service_detail['error_event'].append(el)
                except:
                    pass
                httpcode = 200

                #for s in up_services.keys():
                #    if not up_services[s]:
                #        httpcode = 503

            except Exception as err:
                return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
                httpcode = return_object['httpcode']
        except:
            service_detail = {}

        return_object['detail'] = service_detail
    except Exception as err:
        return_object = str(err)

    apiext_status.update(return_object)
    return (return_object, httpcode)


def list_services():
    """
    GET /system/services

    :param request_inputs:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        service_records = catalog.get_service(user_auth)
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_services_by_name(servicename):
    """
    GET /system/services/<servicename>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        service_records = catalog.get_service(user_auth, servicename=servicename)
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_services_by_name_and_host(servicename, hostid):
    """
    GET /system/services/<servicename>/<hostid>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        service_records = catalog.get_service(user_auth, servicename=servicename, hostid=hostid)
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def delete_service(servicename, hostid):
    """
    DELETE /system/services/<servicename>/<hostid>

    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        return_object = catalog.delete_service(user_auth, servicename=servicename, hostid=hostid)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


