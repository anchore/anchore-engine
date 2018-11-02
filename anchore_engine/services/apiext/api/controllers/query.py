import json
import time

from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.authorization import get_authorizer, RequestingAccountValue, ActionBoundPermission
import anchore_engine.common.pagination
import anchore_engine.common.helpers
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services import internal_client_for
from flask import request

import anchore_engine.common

authorizer = get_authorizer()

@authorizer.requires([])
def query_vulnerabilities(id=None, page=1, limit=None, affected_package=None, affected_package_version=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'id': id, 'page': page, 'limit': limit, 'affected_package': affected_package, 'affected_package_version': None})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs.get('params', {})

    return_object = {}
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        if affected_package_version and not affected_package:
            httpcode = 400
            raise Exception("if affected_package_version is specified, affected_package must also be specified")

        catalog_call_time = 0.0
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(query_digest=request_inputs['pagination_query_digest'])
        except Exception as err:
            timer = time.time()
            result = client.query_vulnerabilities(id=id, affected_package=params.get('affected_package'), affected_package_version=params.get('affected_package_version'))
            catalog_call_time = time.time() - timer

        return_object = anchore_engine.common.pagination.make_response_paginated_envelope(result, envelope_key='vulnerabilities', page=page, limit=limit, dosort=True, sortfunc=lambda x: json.dumps(x), pagination_func=anchore_engine.common.pagination.do_cached_pagination, query_digest=request_inputs['pagination_query_digest'], ttl=max(30.0, catalog_call_time))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def query_images_by_vulnerability(vulnerability_id=None, severity=None, namespace=None, affected_package=None, page=1, limit=None, vendor_only=True):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'vulnerability_id': vulnerability_id, 'severity': severity, 'namespace': namespace, 'affected_package': affected_package, 'page': page, 'limit': limit, 'vendor_only': vendor_only})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs.get('params', {})
    return_object = {}
    httpcode = 500


    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        catalog_call_time = 0.0
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(query_digest=request_inputs['pagination_query_digest'])
        except Exception as err:
            timer = time.time()
            catalog_result = client.query_images_by_vulnerability(vulnerability_id=vulnerability_id, severity=severity, namespace=namespace, affected_package=affected_package, page=page, limit=limit, vendor_only=vendor_only)
            catalog_call_time = time.time() - timer
            result = catalog_result.get('vulnerable_images', [])

        return_object = anchore_engine.common.pagination.make_response_paginated_envelope(result, envelope_key='images', page=page, limit=limit, dosort=True, sortfunc=lambda x: x['image']['imageDigest'], pagination_func=anchore_engine.common.pagination.do_cached_pagination, query_digest=request_inputs['pagination_query_digest'], ttl=max(30.0, catalog_call_time))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def query_images_by_package(name=None, version=None, package_type=None, page=1, limit=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'name': name, 'version': version, 'package_type': package_type, 'page': page, 'limit': limit})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs.get('params', {})

    return_object = {}
    httpcode = 500

    try:
        catalog_call_time = 0.0
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(query_digest=request_inputs['pagination_query_digest'])
        except Exception as err:
            timer = time.time()
            catalog_result = client.query_images_by_package(name=params.get('name'), version=params.get('version'), package_type=params.get('package_type'), page=request_inputs.get('page'), limit=params.get('limit'))
            catalog_call_time = time.time() - timer
            result = catalog_result.get('matched_images', [])

        return_object = anchore_engine.common.pagination.make_response_paginated_envelope(result, envelope_key='images', page=page, limit=limit, dosort=True, sortfunc=lambda x: x['image']['imageDigest'], pagination_func=anchore_engine.common.pagination.do_cached_pagination, query_digest=request_inputs['pagination_query_digest'], ttl=max(30.0, catalog_call_time))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


