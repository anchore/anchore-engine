from connexion import request
import copy
import json
import datetime

# anchore modules
from anchore_engine.clients import catalog, simplequeue, policy_engine
import anchore_engine.services.common
import anchore_engine.subsys.servicestatus
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger

def make_response_service(user_auth, service_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in ['hostid', 'version', 'base_url', 'status', 'status_message', 'servicename']:
            ret[k] = service_record[k]
        if 'short_description' in service_record:
            try:
                ret['service_detail'] = json.loads(service_record['short_description'])
            except:
                ret['service_detail'] = str(service_record['short_description'])

    except Exception as err:
        raise Exception("failed to format service response: " + str(err))

    # global items to filter out
    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)

def make_response_prune_candidate(user_auth, prune_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in ['reason', 'resourcetype', 'userId']:
            ret[k] = prune_record[k]
        ret['created_at'] = datetime.datetime.utcfromtimestamp(prune_record['created_at']).isoformat() + 'Z'

        ret['resource_ids'] = {}
        if 'resource_ids' in prune_record:
            ret['resource_ids'] = copy.deepcopy(prune_record['resource_ids'])

    except Exception as err:
        raise Exception("failed to format prune response: " + str(err))

    return (ret)

def ping():
    """
    GET /

    :return: 200 status with no content
    """
    return

def get_status():
    """
    GET /status

    :return: service status object
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})

    return_object = {}
    httpcode = 500

    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = anchore_engine.subsys.servicestatus.get_status({'hostid': localconfig['host_id'], 'servicename': 'apiext'})
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def get_service_detail():
    """
    GET /system/status

    :return: list of service details
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']

    httpcode = 500
    service_detail = {}

    try:
        try:
            try:
                service_detail['service_states'] = []
                try:
                    up_services = {}
                    service_records = catalog.get_service(user_auth)
                    for service in service_records:
                        el = make_response_service(user_auth, service, params)

                        service_detail['service_states'].append(el)

                        if el['servicename'] not in up_services:
                            up_services[el['servicename']] = 0

                        if el['status']:
                            up_services[el['servicename']] += 1

                except Exception as err:
                    pass

                # Bring back when eventing subsystem is utilized
                #service_detail['error_event'] = []
                #try:
                #    events = catalog.get_event(user_auth)
                #    for event in events:
                #        el = {}
                #        for k in ['message_ts', 'hostId', 'message', 'level']:
                #            el[k] = event[k]
                #        service_detail['error_event'].append(el)
                #except:
                #    pass
                httpcode = 200

            except Exception as err:
                return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
                httpcode = return_object['httpcode']
        except:
            service_detail = {}

        return_object = service_detail
    except Exception as err:
        return_object = str(err)

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

def get_system_feeds():
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        p_client = policy_engine.get_client(user=user_auth[0], password=user_auth[1])
        # do the p.e. feed get call
        response = p_client.list_feeds(include_counts=True)
        return_object = [x.to_dict() for x in response]
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)    

def post_system_feeds(flush=False):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'flush': flush})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        p_client = policy_engine.get_client(user=user_auth[0], password=user_auth[1])
        # do the p.e. feed post call
        return_object = p_client.sync_feeds(force_flush=flush)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)    

def get_system_prune_resourcetypes():
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        return_object = catalog.get_prune_resourcetypes(user_auth)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def get_system_prune_candidates(resourcetype, dangling=True, olderthan=None):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'dangling': dangling, 'olderthan': olderthan})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = {'prune_candidates': []}
    httpcode = 500
    try:
        prune_candidates = catalog.get_prune_candidates(user_auth, resourcetype, dangling=params['dangling'], olderthan=params['olderthan'])
        if prune_candidates:
            for p in prune_candidates['prune_candidates']:
                return_object['prune_candidates'].append(make_response_prune_candidate(user_auth, p, params))
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def post_system_prune_candidates(resourcetype, bodycontent):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        return_object = catalog.perform_prune(user_auth, resourcetype, bodycontent)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def describe_policy():
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        p_client = policy_engine.get_client(user=user_auth[0], password=user_auth[1])
        return_object = p_client.describe_policy()
        if return_object:
            httpcode = 200
        return_object = [x.to_dict() for x in return_object]

    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode







