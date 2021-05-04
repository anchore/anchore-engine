import json
import time

from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.authorization import (
    get_authorizer,
    RequestingAccountValue,
    ActionBoundPermission,
)
import anchore_engine.common.pagination
import anchore_engine.common.helpers
from anchore_engine.clients import grype_wrapper
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.clients.services import internal_client_for
from anchore_engine.subsys import logger
from flask import request

import anchore_engine.common

authorizer = get_authorizer()


def transform_grype_vulnerability(grype_raw_result):
    """
    Receives a single vulnerability_metadata record from grype_db and maps into the data structure engine expects.
    The vulnerability_metadata record may optionally (but in practice should always) have a nested record for the
    related vulnerability record.
    """
    # Create the templated output object
    output_vulnerability = {}
    return_el_template = {
        "id": None,
        "namespace": None,
        "severity": None,
        "link": None,
        "affected_packages": None,
        "description": None,
        "references": None,
        "nvd_data": None,
        "vendor_data": None,
    }
    output_vulnerability.update(return_el_template)

    # Set mapped field values
    output_vulnerability["id"] = grype_raw_result.id
    output_vulnerability["description"] = grype_raw_result.description
    output_vulnerability["severity"] = grype_raw_result.severity

    # TODO What should we do with multiple links. Currently just grabbing the first one
    if grype_raw_result.deserialized_links:
        output_vulnerability["link"] = grype_raw_result.deserialized_links[0]
    else:
        output_vulnerability["link"] = []

    # TODO Not sure yet how these should be mapped
    output_vulnerability["references"] = None
    output_vulnerability["nvd_data"] = []
    output_vulnerability["vendor_data"] = []

    # Get fields from the nested vulnerability object, if it exists
    if grype_raw_result.vulnerability is not None:
        output_vulnerability["namespace"] = grype_raw_result.vulnerability.namespace

        affected_package = {}
        affected_package["name"] = grype_raw_result.vulnerability.package_name
        affected_package["type"] = grype_raw_result.vulnerability.version_format
        affected_package["version"] = grype_raw_result.vulnerability.version_constraint
        output_vulnerability["affected_packages"] = [affected_package]

    return output_vulnerability


def transform_grype_vulnerabilities(grype_raw_results):
    """
    Receives a list of vulnerability_metadata records from grype_db and returns a list of vulnerabilities mapped
    into the data structure engine expects.
    """
    transformed_vulnerabilities = []
    for grype_raw_result in grype_raw_results:
        transformed_vulnerabilities.append(
            transform_grype_vulnerability(grype_raw_result)
        )

    return transformed_vulnerabilities


@authorizer.requires([])
def query_vulnerabilities(
    id=None,
    page=1,
    limit=None,
    affected_package=None,
    affected_package_version=None,
    namespace=None,
):
    """
    Query vulnerabilities using the legacy route to the anchore db from the feeds service, through the policy engine.
    This function calls the common logic around the query in query_vulnerabilities_common, passing through the supplied
    query params along with a callback to the logic that actually executes (and times) the query.
    """

    def legacy_query(request_inputs):
        client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        timer = time.time()
        results = client.query_vulnerabilities(
            vuln_id=request_inputs.get("params", {}).get("id"),
            affected_package=request_inputs.get("params", {}).get("affected_package"),
            affected_package_version=request_inputs.get("params", {}).get(
                "affected_package_version"
            ),
            namespace=request_inputs.get("params", {}).get("namespace"),
        )
        policy_engine_call_time = time.time() - timer
        return results, policy_engine_call_time

    return query_vulnerabilities_common(
        legacy_query,
        id,
        page,
        limit,
        affected_package,
        affected_package_version,
        namespace,
    )


@authorizer.requires([])
def query_vulnerabilities_grype(
    id=None,
    page=1,
    limit=None,
    affected_package=None,
    affected_package_version=None,
    namespace=None,
):
    """
    Query vulnerabilities using the grype db via the grype warapper.
    This function calls the common logic around the query in query_vulnerabilities_common, passing through the supplied
    query params along with a callback to the logic that actually executes (and times) the query. That callback is also
    responsible for calling a function to map the grype_db vulnerability data structure into the sdata strucure engine
    expects.
    """

    def grype_query(request_inputs):
        timer = time.time()
        raw_results = grype_wrapper.query_vulnerabilities(
            vuln_id=request_inputs.get("params", {}).get("id"),
            affected_package=request_inputs.get("params", {}).get("affected_package"),
            affected_package_version=request_inputs.get("params", {}).get(
                "affected_package_version"
            ),
            namespace=request_inputs.get("params", {}).get("namespace"),
        )
        mapped_results = transform_grype_vulnerabilities(raw_results)
        grype_wrapper_call_time = time.time() - timer
        return mapped_results, grype_wrapper_call_time

    return query_vulnerabilities_common(
        grype_query,
        id,
        page,
        limit,
        affected_package,
        affected_package_version,
        namespace,
    )


# TODO Further decompose this function to enable more unit tests
def query_vulnerabilities_common(
    query_callback,
    id=None,
    page=1,
    limit=None,
    affected_package=None,
    affected_package_version=None,
    namespace=None,
):
    request_inputs = anchore_engine.apis.do_request_prep(
        request,
        default_params={
            "id": id,
            "page": page,
            "limit": limit,
            "affected_package": affected_package,
            "affected_package_version": None,
            "namespace": namespace,
        },
    )
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]

    # override to ensure we got the array version, not the string version
    request_inputs.get("params", {})["id"] = id
    request_inputs.get("params", {})["namespace"] = namespace

    params = request_inputs.get("params", {})

    return_object = {}
    httpcode = 500

    try:
        if affected_package_version and not affected_package:
            httpcode = 400
            raise Exception(
                "if affected_package_version is specified, affected_package must also be specified"
            )

        policy_engine_call_time = 0.0
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(
                query_digest=request_inputs["pagination_query_digest"]
            )
        # TODO Raising an Exception to indicate cache non-existence or expiration could
        # mask if there are other exceptions being raised by get_cached_pagination()
        # Feels cleaner to return and catch None or similar, and catch actual exceptions
        except Exception as err:
            results, policy_engine_call_time = query_callback(request_inputs)

        return_object = (
            anchore_engine.common.pagination.make_response_paginated_envelope(
                results,
                envelope_key="vulnerabilities",
                page=page,
                limit=limit,
                dosort=True,
                sortfunc=lambda x: json.dumps(x),
                pagination_func=anchore_engine.common.pagination.do_cached_pagination,
                query_digest=request_inputs["pagination_query_digest"],
                ttl=max(30.0, policy_engine_call_time),
            )
        )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def query_images_by_vulnerability(
    vulnerability_id=None,
    severity=None,
    namespace=None,
    affected_package=None,
    page=1,
    limit=None,
    vendor_only=True,
):
    request_inputs = anchore_engine.apis.do_request_prep(
        request,
        default_params={
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "namespace": namespace,
            "affected_package": affected_package,
            "page": page,
            "limit": limit,
            "vendor_only": vendor_only,
        },
    )
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs.get("params", {})
    return_object = {}
    httpcode = 500

    try:

        policy_engine_call_time = 0.0
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(
                query_digest=request_inputs["pagination_query_digest"]
            )
        except Exception as err:
            client = internal_client_for(
                PolicyEngineClient, ApiRequestContextProxy.namespace()
            )
            timer = time.time()
            pe_result = client.query_images_by_vulnerability(
                user_id=ApiRequestContextProxy.namespace(),
                vulnerability_id=vulnerability_id,
                severity=severity,
                namespace=namespace,
                affected_package=affected_package,
                vendor_only=vendor_only,
            )
            policy_engine_call_time = time.time() - timer
            result = pe_result.get("vulnerable_images", [])

        return_object = (
            anchore_engine.common.pagination.make_response_paginated_envelope(
                result,
                envelope_key="images",
                page=page,
                limit=limit,
                dosort=True,
                sortfunc=lambda x: x["image"]["imageDigest"],
                pagination_func=anchore_engine.common.pagination.do_cached_pagination,
                query_digest=request_inputs["pagination_query_digest"],
                ttl=max(30.0, policy_engine_call_time),
            )
        )

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def query_images_by_package(
    name=None, version=None, package_type=None, page=1, limit=None
):
    request_inputs = anchore_engine.apis.do_request_prep(
        request,
        default_params={
            "name": name,
            "version": version,
            "package_type": package_type,
            "page": page,
            "limit": limit,
        },
    )
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs.get("params", {})

    return_object = {}
    httpcode = 500

    try:
        policy_engine_call_time = 0.0
        try:
            result = anchore_engine.common.pagination.get_cached_pagination(
                query_digest=request_inputs["pagination_query_digest"]
            )
        except Exception as err:
            client = internal_client_for(
                PolicyEngineClient, ApiRequestContextProxy.namespace()
            )
            timer = time.time()
            pe_result = client.query_images_by_package(
                user_id=ApiRequestContextProxy.namespace(),
                name=params.get("name"),
                version=params.get("version"),
                package_type=params.get("package_type"),
            )
            policy_engine_call_time = time.time() - timer
            result = pe_result.get("matched_images", [])

        return_object = (
            anchore_engine.common.pagination.make_response_paginated_envelope(
                result,
                envelope_key="images",
                page=page,
                limit=limit,
                dosort=True,
                sortfunc=lambda x: x["image"]["imageDigest"],
                pagination_func=anchore_engine.common.pagination.do_cached_pagination,
                query_digest=request_inputs["pagination_query_digest"],
                ttl=max(30.0, policy_engine_call_time),
            )
        )

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode
