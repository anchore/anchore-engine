"""
Code for common API handling that is used for all services and apis in the system
"""
import copy
import hashlib
import json

from .context import ApiRequestContextProxy
from anchore_engine.subsys import logger


def do_request_prep(request, default_params=None):
    if default_params is None:
        default_params = {}

    ret = {}
    try:
        ret['userId'] = ApiRequestContextProxy.namespace()
        ret['auth'] = None, None

        ret['method'] = request.method
        ret['bodycontent'] = str(request.get_data(), 'utf-8') if request.get_data() is not None else None
        ret['params'] = default_params
        for param in list(request.args.keys()):
            if type(request.args[param]) in [str, str]:
                if request.args[param].lower() == 'true':
                    val = True
                elif request.args[param].lower() == 'false':
                    val = False
                else:
                    val = request.args[param]
            else:
                val = request.args[param]

            ret['params'][param] = val

        query_signature = copy.deepcopy(ret)
        query_signature['path'] = request.path
        query_signature.get('params', {}).pop('page', None)
        query_signature.get('params', {}).pop('limit', None)
        ret['pagination_query_digest'] = hashlib.sha256(json.dumps(query_signature, sort_keys=True).encode('utf8')).hexdigest()

    except Exception as err:
        logger.error("error processing request parameters - exception: " + str(err))
        raise err

    return(ret)
