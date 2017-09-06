# anchore modules
import json

from connexion import request

# anchore modules
from anchore_engine.clients import catalog
import anchore_engine.services.common


def make_response_subscription(user_auth, subscription_record, params):
    """
    Marshall a json subscription object from db to msg format.

    :param user_auth:
    :param subscription_record:
    :param params:
    :return:
    """
    ret = {}
    userId, pw = user_auth

    try:
        ret = subscription_record
        # for k in ['userId', 'created_at', 'last_updated']:
        #    ret.pop(k, None)
    except Exception as err:
        raise Exception("failed to format subscription response: " + str(err))

    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)


def list_subscriptions():
    """
    GET /subscriptions
    :return: list of subscription objects serialized into json
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        subscription_records = catalog.get_subscription(user_auth)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(user_auth, subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def get_subscription(subscriptionId):
    """
    GET /subscriptions/<subscriptionId>
    :return: list of subscription objects serialized into json
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    params = request_inputs['params']
    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        subscription_records = catalog.get_subscription(user_auth, subscription_id=subscriptionId)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(user_auth, subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def add_subscription(subscription):
    """
    POST /subscriptions

    :return: accepted subscription object as json
    """
    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        subscriptiondata = json.loads(bodycontent)
        subscription_records = catalog.add_subscription(user_auth, subscriptiondata)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(user_auth, subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def update_subscription(subscriptionId, subscription):
    """
    PUT /subscriptions/<subscriptionId>

    :param subscriptionId:
    :param subscription:
    :return:
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        subscriptiondata = json.loads(bodycontent)
        subscription_records = catalog.update_subscription(user_auth, subscriptiondata,
                                                                   subscription_id=subscriptionId)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(user_auth, subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def delete_subscription(subscriptionId):
    """
    DELETE /subscriptions/<subscriptionId>
    :param subscriptionId:
    :return:
    """

    request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        return_object = catalog.delete_subscription(user_auth, subscription_id=subscriptionId)
        if return_object:
            httpcode = 200

    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
