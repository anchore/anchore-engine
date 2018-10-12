import anchore_engine.apis
import anchore_engine.common.helpers
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services import internal_client_for
from flask import request
from anchore_engine.apis.authorization import get_authorizer, RequestingAccountValue, ActionBoundPermission

import anchore_engine.common

authorizer = get_authorizer()


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_events(source_servicename=None, source_hostid=None, resource_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        return_object = client.get_events(source_servicename=source_servicename, source_hostid=source_hostid,
                                           resource_type=resource_type, resource_id=resource_id, level=level, since=since,
                                           before=before, page=page, limit=limit)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_events(before=None, since=None, level=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        return_object = client.delete_events(since=since, before=before, level=level)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_event(eventId):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        return_object = client.get_event(eventId)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_event(eventId):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])

        return_object = client.delete_event(eventId)
        if return_object:
            httpcode = 200
            return_object = None
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode
