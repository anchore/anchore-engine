import json

from connexion import request

# anchore modules
import anchore_engine.apis
from anchore_engine.apis.authorization import get_authorizer, RequestingAccountValue, ActionBoundPermission
import anchore_engine.common.helpers
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
import anchore_engine.common

authorizer = get_authorizer()

def make_response_subscription(subscription_record, params):
    """
    Marshall a json subscription object from db to msg format.

    :param user_auth:
    :param subscription_record:
    :param params:
    :return:
    """
    ret = {}

    try:
        ret = subscription_record
    except Exception as err:
        raise Exception("failed to format subscription response: " + str(err))

    for removekey in ['record_state_val', 'record_state_key']:
        ret.pop(removekey, None)

    return (ret)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_subscriptions(subscription_key=None, subscription_type=None):
    """
    GET /subscriptions
    :return: list of subscription objects serialized into json
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={'subscription_key': subscription_key, 'subscription_type': subscription_type})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']
    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        subscription_records = client.get_subscription(subscription_key=subscription_key, subscription_type=subscription_type)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_subscription(subscriptionId):
    """
    GET /subscriptions/<subscriptionId>
    :return: list of subscription objects serialized into json
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    params = request_inputs['params']
    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        subscription_records = client.get_subscription(subscription_id=subscriptionId)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def add_subscription(subscription):
    """
    POST /subscriptions

    :return: accepted subscription object as json
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        subscriptiondata = json.loads(bodycontent)
        if 'active' not in subscriptiondata:
            subscriptiondata['active'] = False
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        subscription_records = client.add_subscription(subscriptiondata)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def update_subscription(subscriptionId, subscription):
    """
    PUT /subscriptions/<subscriptionId>

    :param subscriptionId:
    :param subscription:
    :return:
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        subscriptiondata = json.loads(bodycontent)
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        subscription_records = client.update_subscription(subscriptiondata, subscription_id=subscriptionId)
        for subscription_record in subscription_records:
            return_object.append(make_response_subscription(subscription_record, params))
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_subscription(subscriptionId):
    """
    DELETE /subscriptions/<subscriptionId>
    :param subscriptionId:
    :return:
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs['userId'])
        return_object = client.delete_subscription(subscription_id=subscriptionId)
        if return_object:
            httpcode = 200

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)
