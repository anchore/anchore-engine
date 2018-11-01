from connexion import request
import copy
import json
import datetime

# anchore modules
import anchore_engine.apis
from anchore_engine.apis.authorization import get_authorizer, ActionBoundPermission

import anchore_engine.common.helpers
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
import anchore_engine.common
import anchore_engine.subsys.servicestatus
import anchore_engine.configuration.localconfig
from anchore_engine.configuration.localconfig import GLOBAL_RESOURCE_DOMAIN
from anchore_engine.apis.context import ApiRequestContextProxy

authorizer = get_authorizer()


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


def ping():
    """
    GET /

    :return: 200 status with api version string
    """
    return ApiRequestContextProxy.get_service().__service_api_version__, 200


def health_noop():
    """
    NOTE: not actually used. This is handled upstream by the twisted service wrapper
    :return:
    """
    return '', 200


def version_noop():
    """
    NOTE: not actually used. This is handled upstream by the twisted service wrapper
    :return:
    """
    return '', 200


@authorizer.requires([]) # Any authenticated user
def get_status():
    """
    GET /status

    :return: service status object
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})

    return_object = {}
    httpcode = 500

    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([])
def get_service_detail():
    """
    GET /system/status

    :return: list of service details
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
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
                    client = internal_client_for(CatalogClient, request_inputs['userId'])
                    service_records = client.get_service()
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
                return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
                httpcode = return_object['httpcode']
        except:
            service_detail = {}

        return_object = service_detail
    except Exception as err:
        return_object = str(err)

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def list_services():
    """
    GET /system/services

    :param request_inputs:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        service_records = client.get_service()
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def get_services_by_name(servicename):
    """
    GET /system/services/<servicename>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        client = CatalogClient(user=user_auth[0], password=user_auth[1])
        service_records = client.get_service(servicename=servicename)
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def get_services_by_name_and_host(servicename, hostid):
    """
    GET /system/services/<servicename>/<hostid>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
        service_records = client.get_service(servicename=servicename, hostid=hostid)
        for service_record in service_records:
            return_object.append(make_response_service(user_auth, service_record, params))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def delete_service(servicename, hostid):
    """
    DELETE /system/services/<servicename>/<hostid>

    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        return_object = client.delete_service(servicename=servicename, hostid=hostid)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def get_system_feeds():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(PolicyEngineClient, userId=ApiRequestContextProxy.namespace())
        # do the p.e. feed get call
        return_object = p_client.list_feeds(include_counts=True)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)    

@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def post_system_feeds(flush=False):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'flush': flush})

    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(PolicyEngineClient, userId=ApiRequestContextProxy.namespace())
        # do the p.e. feed post call
        return_object = p_client.sync_feeds(force_flush=flush)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)    

@authorizer.requires([])
def describe_policy():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(PolicyEngineClient, userId=ApiRequestContextProxy.namespace())
        return_object = p_client.describe_policy()
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode
