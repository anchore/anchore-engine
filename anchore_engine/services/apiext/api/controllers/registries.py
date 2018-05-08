# anchore modules
import datetime
import json
import re

from connexion import request


# anchore modules
from anchore_engine.clients import catalog
import anchore_engine.services.common


def make_response_registry(user_auth, registry_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in ['registry', 'userId', 'registry_user', 'registry_verify', 'registry_type']:
            ret[k] = registry_record[k]

        for datekey in ['last_updated', 'created_at']:
            try:
                ret[datekey] = datetime.datetime.utcfromtimestamp(registry_record[datekey]).isoformat() + 'Z'
            except:
                pass
    except Exception as err:
        raise Exception("failed to format registry response: " + str(err))

    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)


def list_registries():
    """
    GET /registries
    :return:
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        registry_records = catalog.get_registry(user_auth)
        for registry_record in registry_records:
            return_object.append(make_response_registry(user_auth, registry_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_registry(registry):
    """
    GET /registries
    :return:
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        registry_records = catalog.get_registry(user_auth, registry=registry)
        for registry_record in registry_records:
            return_object.append(make_response_registry(user_auth, registry_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def create_registry(registrydata):
    """
    POST /registries

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        registrydata = json.loads(bodycontent)

        try:
            input_registry = registrydata.get('registry', None)

            if input_registry:
                # do some input string checking
                if re.match(".*\/.*", input_registry):
                    raise Exception("input registry name cannot contain '/' characters - valid registry names are of the form <host>:<port> where :<port> is optional")

        except Exception as err:
            httpcode = 409
            raise err

        registry_records = catalog.add_registry(user_auth, registrydata)
        for registry_record in registry_records:
            return_object.append(make_response_registry(user_auth, registry_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def update_registry(registry, registrydata):
    """
    PUT /registries/<id>

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        registrydata = json.loads(bodycontent)

        try:
            input_registry = registrydata.get('registry', None)
            if input_registry:
                # do some input string checking
                if re.match(".*\/.*", input_registry):
                    raise Exception("input registry name cannot contain '/' characters - valid registry names are of the form <host>:<port> where :<port> is optional")
        except Exception as err:
            httpcode = 409
            raise err

        registry_records = catalog.update_registry(user_auth, registry, registrydata)
        for registry_record in registry_records:
            return_object.append(make_response_registry(user_auth, registry_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def delete_registry(registry):
    """
    DELETE /registries

    :param registry:
    :return:
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        return_object = catalog.delete_registry(user_auth, registry=registry)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
