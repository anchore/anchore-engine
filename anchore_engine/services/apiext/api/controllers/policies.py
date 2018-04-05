# anchore modules
import datetime
import hashlib
import json

from connexion import request

# anchore modules
from anchore_engine.clients import catalog, policy_engine
from anchore_engine.clients.policy_engine.generated.rest import ApiException
import anchore_engine.services.common
from anchore_engine.subsys import logger


def make_response_policy(user_auth, policy_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        policy_name = policy_description = None
        if 'name' in policy_record['policybundle']:
            policy_name = policy_record['policybundle']['name']
        if 'description' in policy_record['policybundle']:
            policy_description = policy_record['policybundle']['description']

        latest_ts = 0
        for datekey in ['last_updated', 'created_at']:
            try:
                update_ts = policy_record[datekey] #datetime.datetime.utcfromtimestamp(policy_record[datekey]).isoformat()
                if update_ts > latest_ts:
                    latest_ts = update_ts
            except:
                pass

            try:
                update_ts = policy_record['policybundlemeta'][datekey] #datetime.datetime.utcfromtimestamp(policy_record['policybundlemeta'][datekey]).isoformat()
                if update_ts > latest_ts:
                    latest_ts = update_ts
            except:
                pass

        policy_record['created_at'] = datetime.datetime.utcfromtimestamp(policy_record['created_at']).isoformat()
        policy_record['last_updated'] = datetime.datetime.utcfromtimestamp(latest_ts).isoformat()

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

def list_policies(detail=None):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'detail': False})
    user_auth = request_inputs['auth']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        logger.debug('Listing policies')

        try:
            policy_records = catalog.get_policy(user_auth)
        except Exception as err:
            httpcode = 404
            raise Exception("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))

        if policy_records:
            httpcode = 200
            ret = []
            for policy_record in policy_records:
                ret.append(make_response_policy(user_auth, policy_record, params))
            return_object = ret
        else:
            httpcode = 404
            raise Exception('no policies found for user')
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def add_policy(bundle):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        logger.debug('Adding policy')

        jsondata = json.loads(bodycontent)

        # schema check
        try:
            p_client = policy_engine.get_client(user=user_auth[0], password=user_auth[1])
            response = p_client.validate_bundle(policy_bundle=jsondata)

            if not response.valid:
                httpcode = 400
                return_object = anchore_engine.services.common.make_response_error('Bundle failed validation', in_httpcode=400, detail={'validation_details': [x.to_dict() for x in response.validation_details]})
                return (return_object, httpcode)

        except ApiException as err:
            raise Exception('Error response from policy service during bundle validation. Validation could not be performed: {}'.format(err))

        if 'id' in jsondata and jsondata['id']:
            policyId = jsondata['id']
        else:
            policyId = hashlib.md5(str(userId + ":" + jsondata['name'])).hexdigest()
            jsondata['id'] = policyId

        try:
            policybundle = jsondata
            policy_record = catalog.add_policy(user_auth, policybundle)
        except Exception as err:
            raise Exception("cannot store policy data to catalog - exception: " + str(err))

        if policy_record:
            return_object = make_response_policy(user_auth, policy_record, params)
            httpcode = 200
        else:
            raise Exception('failed to add policy to catalog DB')
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_policy(policyId, detail=None):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'detail': True})
    user_auth = request_inputs['auth']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth
    try:
        logger.debug('Get policy by bundle Id')

        try:
            policy_records = catalog.get_policy(user_auth, policyId=policyId)
        except Exception as err:
            logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
            policy_records = []

        if policy_records:
            ret = []

            for policy_record in policy_records:
                ret.append(make_response_policy(user_auth, policy_record, params))
            return_object = ret
            httpcode = 200
        else:
            httpcode = 404
            raise Exception("cannot locate specified policyId")
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def update_policy(bundle, policyId, active=False):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'active': active})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        logger.debug("Updating policy")

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
            policy_records = catalog.get_policy(user_auth, policyId=policyId)
        except Exception as err:
            logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
            policy_records = []

        if policy_records:
            policy_record = policy_records[0]
            if policy_record['active'] and not jsondata['active']:
                httpcode = 500
                raise Exception("cannot deactivate an active policy - can only activate an inactive policy")
            elif policyId != jsondata['policyId']:
                httpcode = 500
                raise Exception("policyId in route is different from policyId in payload")

            policy_record.update(jsondata)
            policy_record['policyId'] = policyId

            # schema check
            try:
                p_client = policy_engine.get_client(user=user_auth[0], password=user_auth[1])
                response = p_client.validate_bundle(policy_bundle=jsondata['policybundle'])

                if not response.valid:
                    httpcode = 400
                    return_object = anchore_engine.services.common.make_response_error('Bundle failed validation',
                                                                                       in_httpcode=400, detail={
                            'validation_details': [x.to_dict() for x in response.validation_details]})
                    return (return_object, httpcode)

            except ApiException as err:
                raise Exception(
                    'Error response from policy service during bundle validation. Validation could not be performed: {}'.format(
                        err))

            return_policy_record = catalog.update_policy(user_auth, policyId, policy_record=policy_record)
            return_object = [make_response_policy(user_auth, return_policy_record, params)]
            httpcode = 200
        else:
            httpcode = 404
            raise Exception("cannot locate specified policyId")
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']
    return (return_object, httpcode)


def delete_policy(policyId):
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        logger.debug("Delete policy")

        try:
            try:
                policy_records = catalog.get_policy(user_auth, policyId=policyId)
            except Exception as err:
                logger.warn("unable to get policy_records for user (" + str(userId) + ") - exception: " + str(err))
                policy_records = []

            if not policy_records:
                rc = True
            else:
                policy_record = policy_records[0]
                if policy_record['active']:
                    httpcode = 500
                    raise Exception(
                        "cannot delete an active policy - activate a different policy then delete this one")

            rc = catalog.delete_policy(user_auth, policyId=policyId)
        except Exception as err:
            raise err

        if rc:
            httpcode = 200
            return_object = "deleted"
        else:
            httpcode = 500
            raise Exception('not deleted')
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
