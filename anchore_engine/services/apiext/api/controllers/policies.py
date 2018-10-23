import datetime
import hashlib
import json

from connexion import request

# anchore modules
import anchore_engine.apis
import anchore_engine.common.helpers
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient

import anchore_engine.common
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.apis.authorization import get_authorizer, RequestingAccountValue, ActionBoundPermission

authorizer = get_authorizer()


def make_response_policy(policy_record, params):
    ret = {}

    try:
        policy_name = policy_description = None
        if 'name' in policy_record['policybundle']:
            policy_name = policy_record['policybundle']['name']
        if 'description' in policy_record['policybundle']:
            policy_description = policy_record['policybundle']['description']

        latest_ts = 0
        for datekey in ['last_updated', 'created_at']:
            try:
                update_ts = policy_record[datekey] 
                if update_ts > latest_ts:
                    latest_ts = update_ts
            except:
                pass

            try:
                update_ts = policy_record['policybundlemeta'][datekey] 
                if update_ts > latest_ts:
                    latest_ts = update_ts
            except:
                pass

        policy_record['created_at'] = datetime.datetime.utcfromtimestamp(policy_record['created_at']).isoformat() + 'Z'
        policy_record['last_updated'] = datetime.datetime.utcfromtimestamp(latest_ts).isoformat() + 'Z'

        if 'detail' in params and not params['detail']:
            # strip out the detail
            policy_record['policybundle'] = {}
            policy_record['policybundlemeta'] = {}

        ret = policy_record
        if policy_name:
            ret['name'] = policy_name
        if policy_description:
            ret['description'] = policy_description

    except Exception as err:
        raise Exception("failed to format policy eval response: " + str(err))

    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_policies(detail=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'detail': False})
    user_auth = request_inputs['auth']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId = request_inputs['userId']

    try:
        logger.debug('Listing policies')
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        try:
            policy_records = client.list_policies()
            httpcode = 200
        except Exception as err:
            logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
            raise err

        if policy_records:
            ret = []
            for policy_record in policy_records:
                ret.append(make_response_policy(policy_record, params))
            return_object = ret

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def add_policy(bundle):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId = request_inputs['userId']

    try:
        logger.debug('Adding policy')
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        jsondata = json.loads(bodycontent)

        # schema check
        try:
            localconfig = anchore_engine.configuration.localconfig.get_config()
            user_auth = localconfig['system_user_auth']
            verify = localconfig.get('internal_ssl_verify', True)

            p_client = internal_client_for(PolicyEngineClient, userId=userId)
            response = p_client.validate_bundle(jsondata)
            if not response.get('valid', False):
                httpcode = 400
                return_object = anchore_engine.common.helpers.make_response_error('Bundle failed validation', in_httpcode=400, detail={'validation_details': [x.to_dict() for x in response.validation_details]})
                return (return_object, httpcode)

        except Exception as err:
            raise Exception('Error response from policy service during bundle validation. Validation could not be performed: {}'.format(err))

        if 'id' in jsondata and jsondata['id']:
            policyId = jsondata['id']
        else:
            policyId = hashlib.md5(str(userId + ":" + jsondata['name']).encode('utf8')).hexdigest()
            jsondata['id'] = policyId

        try:
            policybundle = jsondata
            policy_record = client.add_policy(policybundle)
        except Exception as err:
            raise Exception("cannot store policy data to catalog - exception: " + str(err))

        if policy_record:
            return_object = make_response_policy(policy_record, params)
            httpcode = 200
        else:
            raise Exception('failed to add policy to catalog DB')
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_policy(policyId, detail=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'detail': True})
    user_auth = request_inputs['auth']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth
    try:
        logger.debug('Get policy by bundle Id')
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        try:
            policy_record = client.get_policy(policyId=policyId)
        except Exception as err:
            logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
            raise err


        if policy_record:
            ret = []
            ret.append(make_response_policy(policy_record, params))
            return_object = ret
            httpcode = 200
        else:
            httpcode = 404
            raise Exception("cannot locate specified policyId")
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def update_policy(bundle, policyId, active=False):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'active': active})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        logger.debug("Updating policy")
        client = internal_client_for(CatalogClient, request_inputs['userId'])

        if not bodycontent:
            bodycontent = '{}'

        jsondata = json.loads(bodycontent)

        if not jsondata:
            jsondata['policyId'] = policyId

        if active:
            jsondata['active'] = True
        elif 'active' not in jsondata:
            jsondata['active'] = False

        try:
            policy_record = client.get_policy(policyId=policyId)
        except Exception as err:
            logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
            raise err

        if policy_record:
            if policy_record['active'] and not jsondata['active']:
                httpcode = 500
                raise Exception("cannot deactivate an active policy - can only activate an inactive policy")
            elif policyId != jsondata['policyId']:
                httpcode = 500
                raise Exception("policyId in route is different from policyId in payload: {} != {}".format(policyId, jsondata['policyId']))

            policy_record.update(jsondata)
            policy_record['policyId'] = policyId

            # schema check
            try:
                localconfig = anchore_engine.configuration.localconfig.get_config()
                user_auth = localconfig['system_user_auth']
                verify = localconfig.get('internal_ssl_verify', True)
                p_client = internal_client_for(PolicyEngineClient, userId)
                response = p_client.validate_bundle(jsondata['policybundle'])
                if not response.get('valid', False):
                    httpcode = 400
                    return_object = anchore_engine.common.helpers.make_response_error('Bundle failed validation',
                                                                                      in_httpcode=400, detail={
                            'validation_details': [x.to_dict() for x in response.validation_details]})
                    return (return_object, httpcode)

            except Exception as err:
                raise Exception(
                    'Error response from policy service during bundle validation. Validation could not be performed: {}'.format(
                        err))

            return_policy_record = client.update_policy(policyId, policy_record=policy_record)
            return_object = [make_response_policy(return_policy_record, params)]
            httpcode = 200
        else:
            httpcode = 404
            raise Exception("cannot locate specified policyId")
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']
    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_policy(policyId):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        logger.debug("Delete policy {}".format(policyId))
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        try:
            try:
                policy_record = client.get_policy(policyId=policyId)
            except Exception as err:
                logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
                raise err

            if not policy_record:
                rc = True
            else:
                if policy_record['active']:
                    httpcode = 500
                    raise Exception(
                        "cannot delete an active policy - activate a different policy then delete this one")

            rc = client.delete_policy(policyId=policyId)
        except Exception as err:
            raise err

        if rc:
            httpcode = 200
            return_object = "deleted"
        else:
            httpcode = 500
            raise Exception('not deleted')
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
