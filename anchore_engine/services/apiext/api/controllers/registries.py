import datetime
import json
import re

from connexion import request

# anchore modules
import anchore_engine.apis
import anchore_engine.common
import anchore_engine.common.helpers
from anchore_engine.apis.authorization import (
    ActionBoundPermission,
    RequestingAccountValue,
    get_authorizer,
)
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient

authorizer = get_authorizer()


def make_response_registry(user_auth, registry_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in [
            "registry",
            "userId",
            "registry_user",
            "registry_verify",
            "registry_type",
            "registry_name",
        ]:
            ret[k] = registry_record[k]

        for datekey in ["last_updated", "created_at"]:
            try:
                ret[datekey] = (
                    datetime.datetime.utcfromtimestamp(
                        registry_record[datekey]
                    ).isoformat()
                    + "Z"
                )
            except:
                pass
    except Exception as err:
        raise Exception("failed to format registry response: " + str(err))

    for removekey in ["record_state_val", "record_state_key"]:
        ret.pop(removekey, None)

    return ret


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_registries():
    """
    GET /registries
    :return:
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        registry_records = client.get_registry()
        for registry_record in registry_records:
            return_object.append(
                make_response_registry(user_auth, registry_record, params)
            )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_registry(registry):
    """
    GET /registries
    :return:
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        registry_records = client.get_registry(registry=registry)
        for registry_record in registry_records:
            return_object.append(
                make_response_registry(user_auth, registry_record, params)
            )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def create_registry(registrydata, validate=True):
    """
    POST /registries

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(
        request, default_params={"validate": validate}
    )
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500

    try:
        registrydata = json.loads(bodycontent)
        try:
            input_registry = registrydata.get("registry", None)

            if input_registry:
                # do some input string checking
                errmsg = None
                if re.match(".*/+$", input_registry):
                    errmsg = (
                        "input registry name cannot end with trailing '/' characters"
                    )
                elif re.match("^http[s]*://", input_registry):
                    errmsg = "input registry name must start with a hostname/ip, without URI schema (http://, https://)"

                if errmsg:
                    raise Exception(errmsg)

        except Exception as err:
            httpcode = 409
            raise err

        client = internal_client_for(CatalogClient, request_inputs["userId"])
        registry_records = client.add_registry(registrydata, validate=validate)
        for registry_record in registry_records:
            return_object.append(
                make_response_registry(user_auth, registry_record, params)
            )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def update_registry(registry, registrydata, validate=True):
    """
    PUT /registries/<id>

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(
        request, default_params={"validate": validate}
    )
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500

    try:
        registrydata = json.loads(bodycontent)

        try:
            input_registry = registrydata.get("registry", None)
            if input_registry:
                if input_registry != registry:
                    raise Exception(
                        "registry name in path does not equal registry name in body"
                    )

                # do some input string checking
                # if re.match(".*\/.*", input_registry):
                #    raise Exception("input registry name cannot contain '/' characters - valid registry names are of the form <host>:<port> where :<port> is optional")
        except Exception as err:
            httpcode = 409
            raise err

        client = internal_client_for(CatalogClient, request_inputs["userId"])
        registry_records = client.update_registry(
            registry, registrydata, validate=validate
        )
        for registry_record in registry_records:
            return_object.append(
                make_response_registry(user_auth, registry_record, params)
            )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_registry(registry):
    """
    DELETE /registries

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object = client.delete_registry(registry=registry)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode
