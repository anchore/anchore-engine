import copy
import json
import datetime

from anchore_engine.clients import catalog
from anchore_engine.subsys import logger
from flask import request

import anchore_engine.services.common

def query_images_by_vulnerability(id=None, severity=None, page=1, limit=100, vendor_only=True):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'id': id, 'severity': severity, 'page': page, 'limit': limit, 'vendor_only': vendor_only})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        result = catalog.query_images_by_vulnerability(user_auth, id=id, severity=severity, page=page, limit=limit, vendor_only=vendor_only)
        return_object = anchore_engine.services.common.make_response_paginated_envelope(result['vulnerable_images'], envelope_key='vulnerable_images', page=page, limit=limit, dosort=True, pagination_func=anchore_engine.services.common.do_simple_pagination)

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


