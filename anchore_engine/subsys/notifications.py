import json
import uuid

from anchore_engine.clients.services import http
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.clients.services import internal_client_for

def queue_notification(userId, subscription_key, subscription_type, payload):
    
    #localconfig = anchore_engine.configuration.localconfig.get_config()
    #system_user_auth = localconfig['system_user_auth']
    q_client = internal_client_for(SimpleQueueClient, None)

    rc = False
    try:
        nobj = {
            'userId': userId,
            'subscription_key': subscription_key,
            'notificationId': str(uuid.uuid4()),
        }
        if payload:
            nobj.update(payload)
        if not q_client.is_inqueue(subscription_type, nobj):
            rc = q_client.enqueue(subscription_type, nobj)
    except Exception as err:
        logger.warn("failed to create/enqueue notification")
        raise err

    return rc

def make_notification(user_record, subscription_type, notification):
    ret = {}
    try:
        payload_data = {
            'notification_user': user_record['name'],
            'notification_user_email': user_record['email'],
            'notification_type': subscription_type,
            'notification_payload': notification
        }
        json.dumps(payload_data)
        ret = payload_data
    except Exception as err:
        raise Exception("cannot prepare notification - exception: " + str(err))

    return ret


def notify(user_record, notification):
    """
    Notifications are sent periodically based on polling a queue for a particular type of subscription
    (anchore_engine.common.subscription_types + [event_log_type])

    This method is responsible for actually distributing notifications according to the notification_modes defined
    below (currently only webhook supported)
    Note: The notification passed in is not coming from make_notification method above, but rather from
    db_queues.get_all, which passes a QueueItem (see anchore_engine/subsys/catalog.py) serialized as a dict
    (data field is a json)

    :param user_record: the account sending the notification
    :param notification: a dict loaded from db_queues.get_all. Ex:
        {
          "queueId": "subscription type actual",
          "userId": "acct name",
          "queueName": "string",
          "dataId": "notificationId",
          "created_at": 981173106,
          "last_updated": 981173106,
          "record_state_key": "active",
          "record_state_val": "",
          "tries": 0,
          "max_tries": 981173206,
          "data": {
            "notification_user": "account name",
            "notification_user_email": "account email",
            "notification_type": "same as subscription type",
            "notification_payload": {
              "userId": "from original notification",
              "notificationId": "from original notification",
              "subscription_type": " from event details",
              "subscription_key": "from event resource id"
            }
          }
        }
    :return: boolean (True if successful)
    """
    notification_modes = ['webhook']

    logger.debug("sending notification: " + json.dumps(notification, indent=4))
    for notification_mode in notification_modes:
        if notification_mode == 'webhook':
            rc = do_notify_webhook(user_record, notification)

    return True


def do_notify_webhook(user_record, notification):

    notification_type = notification['data']['notification_type']
    user = pw = None
    subvars = [('<userId>', user_record['name']), ('<notification_type>', notification_type)]

    try:
        payload = json.dumps(notification)
    except Exception as err:
        raise Exception("could not prepare notification as JSON - exception: " + str(err))

    webhooks = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    if 'webhooks' in localconfig:
        webhooks.update(localconfig['webhooks'])

    if webhooks:
        rootuser = webhooks.pop('webhook_user', None)
        rootpw = webhooks.pop('webhook_pass', None)
        rootverify = webhooks.pop('ssl_verify', None)
            
        for ntype in [notification_type, 'general']:
            if ntype in webhooks:
                webhook = webhooks[ntype]
                
                user = webhook.pop('webhook_user', rootuser)
                pw = webhook.pop('webhook_pass', rootpw)
                verify = webhook.pop('ssl_verify', rootverify)

                if not user and not pw:
                    auth=None
                else:
                    auth = (user, pw)

                url = webhook['url']
                for subkey,subval in subvars:
                    url = url.replace(subkey, subval)

                try:
                    logger.debug("webhook post: " + str(url) + " : " + str(notification))
                    #result = http.post(url, data=payload, auth=auth, timeout=2.0, verify=verify)
                    headers = {'Content-Type': 'application/json'}
                    result = http.anchy_post(url, data=payload, auth=auth, timeout=2.0, verify=verify, headers=headers)
                    logger.debug("webhook response: " + str(result))
                    return True
                except Exception as err:
                    raise Exception("failed to post notification to webhook - exception: " + str(err))
            
    logger.debug("warning: notification generated, but no matching webhook could be found in config to send it to - dropping notification")
    return False

