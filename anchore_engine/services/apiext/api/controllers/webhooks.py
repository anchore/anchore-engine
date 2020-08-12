import copy
import datetime
import json
import uuid

from connexion import request

# anchore modules
import anchore_engine.apis
import anchore_engine.common
import anchore_engine.common.helpers
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine import db
from anchore_engine.apis.authorization import get_authorizer
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.subsys import notifications
from anchore_engine.subsys.identities import IdentityManagerFactory

authorizer = get_authorizer()
manager_factory = IdentityManagerFactory(localconfig.get_config())

TEST_NOTIFICATION_TEMPLATE = {
    "queueId": "replaced_at_runtime",
    "userId": "replaced_at_runtime",
    "dataId": "test_notification_id {}",
    "created_at": 0,  # replaced at runtime
    "last_updated": 0,  # replaced at runtime
    "record_state_key": "active",
    "record_state_val": "",
    "tries": 0,
    "max_tries": 0,
    "data": {
        "notification_user": "replaced_at_runtime",
        "notification_user_email": "replaced_at_runtime",
        "notification_type": "replaced_at_runtime",
        "notification_payload": {
            "userId": "replaced_at_runtime",
            "notificationId": "test_notification_id {}",
            "subscription_type": "replaced_at_runtime",
            "subscription_key": "randomly_generated-{}"
        }
    }
}


@authorizer.requires([])
def test_webhook(webhook_type='general'):
    """
    This method adds the capability to test a Webhook delivery of a test notification

    :param webhook_type: the type of webhook to send
    """
    logger.debug("Testing webhook for type '{}'".format(webhook_type))
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = {}
    httpcode = 500
    try:
        webhooks = {}

        # Load Webhook configurations, and select webhook according to webhook_type
        localconfig = anchore_engine.configuration.localconfig.get_config()
        if 'webhooks' in localconfig:
            webhooks.update(localconfig['webhooks'])

        if not webhooks:
            httpcode = 400
            return_object = anchore_engine.common.helpers.make_response_error('Webhooks Configuration not found',
                                                                              in_httpcode=httpcode)
            return return_object, httpcode

        webhook = webhooks[webhook_type]
        if not webhook:
            httpcode = 400
            return_object = anchore_engine.common.helpers.make_response_error(
                "No Webhook Configuration found for type={}".format(webhook_type),
                in_httpcode=httpcode
            )
            return return_object, httpcode

        return send_test_notification(webhooks, webhook, request_inputs, webhook_type)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return return_object, httpcode


def get_test_notification(webhook_type, request_inputs):
    """
    Build a test notification payload (format should mirror what's returned by get_webhook_schema)
    :param webhook_type: type of webhook to send
    :param request_inputs: metadata from request to test webhook
    """

    notification = copy.deepcopy(TEST_NOTIFICATION_TEMPLATE)
    notification['queueId'] = webhook_type
    notification['userId'] = request_inputs['userId']
    notification['queueName'] = webhook_type
    notification['dataId'] = TEST_NOTIFICATION_TEMPLATE['dataId'].format(uuid.uuid4())
    current_ts = int(datetime.datetime.now().timestamp())
    notification['created_at'] = current_ts
    notification['last_updated'] = current_ts
    notification['max_tries'] = current_ts + 3600

    data = {'notification_user': request_inputs['userId']}
    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        data['notification_user_email'] = mgr.get_account(request_inputs['userId'])['email']

    data['notification_type'] = webhook_type

    notification_id = TEST_NOTIFICATION_TEMPLATE['data']['notification_payload']['notificationId'].format(uuid.uuid4())
    subscription_key = TEST_NOTIFICATION_TEMPLATE['data']['notification_payload']['subscription_key']\
        .format(uuid.uuid4())
    notification_payload = {
        'userId': request_inputs['userId'],
        'notificationId': notification_id,
        'subscription_type': webhook_type,
        'subscription_key': subscription_key
    }

    data['notification_payload'] = notification_payload
    notification['data'] = data

    logger.debug("Test Notification JSON: {}".format(notification))

    return notification


def send_test_notification(webhooks, webhook, request_inputs, webhook_type):
    """
    This Method actually gathers all the parameters needed for notifications to actually send the webhook

    :param webhooks: webhooks loaded from localconfig
    :param webhook: the webhook object for webhook_type
    :param request_inputs: the request inputs (used to resolve userId)
    :param webhook_type: webhook type to send (used to build payload)
    :return: result of webhook and http code (200 if successful, 500 if we fail to build test notification or payload
    """
    httpcode = 500
    rootuser = webhooks.pop('webhook_user', None)
    rootpw = webhooks.pop('webhook_pass', None)
    rootverify = webhooks.pop('ssl_verify', None)

    subvars = [('<userId>', request_inputs['userId']), ('<notification_type>', 'test')]

    try:
        notification = get_test_notification(webhook_type, request_inputs)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        return return_object, httpcode

    logger.info('build payload')
    try:
        payload = json.dumps(notification)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
        return return_object, httpcode

    return notifications.do_notify_webhook_type(webhook=webhook,
                                                user=webhook.pop('webhook_user', rootuser),
                                                pw=webhook.pop('webhook_pass', rootpw),
                                                verify=webhook.pop('ssl_verify', rootverify),
                                                subvars=subvars,
                                                payload=payload), 200
