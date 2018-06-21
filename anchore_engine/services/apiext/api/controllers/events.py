import copy
import json
import datetime

from anchore_engine.clients import catalog
from anchore_engine.subsys import logger
from flask import request

import anchore_engine.services.common


def list_events(source_servicename=None, source_hostid=None, resource_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        return_object = catalog.get_events(user_auth, source_servicename=source_servicename, source_hostid=source_hostid,
                                           resource_type=resource_type, resource_id=resource_id, level=level, since=since,
                                           before=before, page=page, limit=limit)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def delete_events(before=None, since=None, level=None):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        return_object = catalog.delete_events(user_auth, since=since, before=before, level=level)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_event(eventId):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        return_object = catalog.get_event(user_auth, eventId)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def delete_event(eventId):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        return_object = catalog.delete_event(user_auth, eventId)
        if return_object:
            httpcode = 200
            return_object = None
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
