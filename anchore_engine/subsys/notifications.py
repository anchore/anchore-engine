import json
import uuid
import jsonschema

import anchore_engine.configuration.localconfig
from anchore_engine.apis.context import ApiRequestContextProxy
import anchore_engine.configuration.localconfig
from anchore_engine.clients.services import http
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.db.entities.common import anchore_now
from anchore_engine.subsys import logger

NOTIFICATION_MAPPING = {
    "policy_eval": "PolicyEvalNotification",
    "tag_update": "TagUpdateNotification",
    "vuln_update": "VulnUpdateNotification",
    "analysis_update": "AnalysisUpdateNotification",
}


class NotificationValidationError(Exception):
    def __init__(self, user_id, notification_id, subscription_type):
        super(NotificationValidationError, self).__init__(
            "Notification Payload failed schema validation, cannot deliver. user_id={}, notification_id={}, subscription_type={}".format(
                user_id, notification_id, subscription_type
            )
        )
        self.user_id = user_id
        self.notification_id = notification_id
        self.subscription_type = subscription_type


class Notification(object):
    def __init__(self, queue_id, user_id, user_email):
        self.queue_id = queue_id
        self.user_id = user_id
        self.data_id = str(uuid.uuid4())
        self.last_updated = anchore_now()
        self.created_at = anchore_now()
        self.record_state_key = "active"
        self.tries = 0
        self.max_tries = self.created_at + 3600
        self.data = BaseNotificationData(user_id, user_email, queue_id)

    def to_dict(self):
        n_dict = dict()
        n_dict["queueId"] = self.queue_id
        n_dict["userId"] = self.user_id
        n_dict["dataId"] = self.data_id
        n_dict["created_at"] = self.created_at
        n_dict["last_updated"] = self.last_updated
        n_dict["record_state_key"] = self.record_state_key
        n_dict["tries"] = self.tries
        n_dict["max_tries"] = self.max_tries
        n_dict["data"] = self.data.to_dict()

        return n_dict

    def to_json(self):
        return json.dumps(self.to_dict())


class BaseNotificationData(object):
    def __init__(self, user_id, user_email, notification_type):
        self.notification_user = user_id
        self.notification_user_email = user_email
        self.notification_type = notification_type
        self.notification_payload = self.build_payload(notification_type)

    def build_payload(self, notification_type):
        if notification_type == "policy_eval":
            return TestPolicyEvalNotificationPayload(
                self.notification_user, notification_type
            )
        elif notification_type == "tag_update":
            return TestTagUpdateNotificationPayload(
                self.notification_user, notification_type
            )
        elif notification_type == "vuln_update":
            return TestVulnUpdateNotificationPayload(
                self.notification_user, notification_type
            )
        elif notification_type == "analysis_update":
            return TestAnalysisUpdateNotificationPayload(
                self.notification_user, notification_type
            )

    def to_dict(self):
        data = dict()
        data["notification_user"] = self.notification_user
        data["notification_user_email"] = self.notification_user_email
        data["notification_type"] = self.notification_type
        data["notification_payload"] = self.notification_payload.to_dict()
        return data


class BaseNotificationPayload(object):
    def __init__(self, user_id, subscription_type):
        self.user_id = user_id
        self.subscription_key = str(uuid.uuid4())
        self.subscription_type = subscription_type
        self.notification_id = str(uuid.uuid4())

    def to_dict(self):
        payload = dict()
        payload["userId"] = self.user_id
        payload["subscription_key"] = self.subscription_key
        payload["subscription_type"] = self.subscription_type
        payload["notificationId"] = self.notification_id
        return payload


class TestPolicyEvalNotificationPayload(BaseNotificationPayload):
    class Eval(object):
        def __init__(self):
            self.image_digest = "test_image_digest"
            self.status = "pass"

        def to_dict(self):
            eval_dict = dict()
            eval_dict["image_digest"] = self.image_digest
            eval_dict["status"] = self.status
            return eval_dict

    def __init__(self, user_id, subscription_type):
        super().__init__(user_id, subscription_type)
        self.curr_eval = self.Eval()
        self.last_eval = self.Eval()
        self.annotations = ["test"]

    def to_dict(self):
        payload = super().to_dict()
        payload["curr_eval"] = self.curr_eval.to_dict()
        payload["last_eval"] = self.last_eval.to_dict()
        payload["annotations"] = self.annotations
        return payload


class TestTagUpdateNotificationPayload(BaseNotificationPayload):
    def __init__(self, user_id, subscription_type):
        super().__init__(user_id, subscription_type)
        self.curr_eval = ["test_image_digest"]
        self.last_eval = ["test_image_digest"]
        self.annotations = ["test"]

    def to_dict(self):
        payload = super().to_dict()
        payload["curr_eval"] = self.curr_eval
        payload["last_eval"] = self.last_eval
        payload["annotations"] = self.annotations
        return payload


class TestVulnUpdateNotificationPayload(BaseNotificationPayload):
    class VulnDiffResult(object):
        def __init__(self):
            self.added = ["test1"]
            self.updated = ["test2"]
            self.removed = ["test3"]

        def to_dict(self):
            diff = dict()
            diff["added"] = self.added
            diff["updated"] = self.updated
            diff["removed"] = self.removed
            return diff

    def __init__(self, user_id, subscription_type):
        super().__init__(user_id, subscription_type)
        self.diff_vulnerability_result = self.VulnDiffResult()
        self.image_digest = "test_image_digest"
        self.annotations = ["test"]

    def to_dict(self):
        payload = super().to_dict()
        payload["diff_vulnerability_result"] = self.diff_vulnerability_result.to_dict()
        payload["image_digest"] = self.image_digest
        payload["annotations"] = self.annotations
        return payload


class TestAnalysisUpdateNotificationPayload(BaseNotificationPayload):
    class AnalysisUpdateEval:
        def __init__(self, status):
            self.analysis_status = status
            self.annotations = ["test"]
            self.image_digest = "test_image_digest"

        def to_dict(self):
            aue = dict()
            aue["analysis_status"] = self.analysis_status
            aue["annotations"] = self.annotations
            aue["image_digest"] = self.image_digest
            return aue

    def __init__(self, user_id, subscription_type):
        super().__init__(user_id, subscription_type)
        self.curr_eval = self.AnalysisUpdateEval("analyzed")
        self.last_eval = self.AnalysisUpdateEval("analyzing")
        self.annotations = ["test"]

    def to_dict(self):
        payload = super().to_dict()
        payload["curr_eval"] = self.curr_eval.to_dict()
        payload["last_eval"] = self.last_eval.to_dict()
        payload["annotations"] = self.annotations
        return payload


def queue_notification(userId, subscription_key, subscription_type, payload):
    """
    Put a Notification in the Queue!
    """
    q_client = internal_client_for(SimpleQueueClient, None)

    rc = False
    try:
        nobj = {
            "userId": userId,
            "subscription_key": subscription_key,
            "notificationId": str(uuid.uuid4()),
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
            "notification_user": user_record["name"],
            "notification_user_email": user_record["email"],
            "notification_type": subscription_type,
            "notification_payload": notification,
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
    notification_modes = ["webhook"]

    logger.debug("sending notification: " + json.dumps(notification, indent=4))

    validate_schema(notification)

    for notification_mode in notification_modes:
        if notification_mode == "webhook":
            rc = do_notify_webhook(user_record, notification)

    return True


def validate_schema(notification):
    """
    Check if the notification conforms to the Schema outlined in the Swagger Spec.
    Also only do this for the types we know (policy_eval, vuln_update, tag_update, analysis_update)

    :param notification: notification object to deliver
    """
    ret = False

    notification_type = notification.get("data", {}).get("notification_type", None)
    if notification_type not in NOTIFICATION_MAPPING.keys():
        logger.debug(
            "Not doing Schema validation for Notification Type: {}".format(
                notification_type
            )
        )
        return ret
    elif not notification_type:
        logger.warn("Notification Type not resolved: {}".format(notification))
        return ret

    notification_schema_definition = NOTIFICATION_MAPPING.get(
        notification_type, "NotificationBase"
    )

    spec = ApiRequestContextProxy.get_service().api_spec
    schema = spec.get("definitions", {}).get(notification_schema_definition)
    try:
        jsonschema.validate(notification, schema)
        ret = True
    except jsonschema.ValidationError as e:
        logger.error(
            "Notification does not pass validation, still delivering for backwards compatibility: {}".format(
                e
            )
        )
        ret = False

    return ret


def do_notify_webhook(user_record, notification):

    notification_type = notification["data"]["notification_type"]
    subvars = [
        ("<userId>", user_record["name"]),
        ("<notification_type>", notification_type),
    ]

    try:
        payload = json.dumps(notification)
    except Exception as err:
        raise Exception(
            "could not prepare notification as JSON - exception: " + str(err)
        )

    webhooks = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    if "webhooks" in localconfig:
        webhooks.update(localconfig["webhooks"])

    if webhooks:
        rootuser = webhooks.pop("webhook_user", None)
        rootpw = webhooks.pop("webhook_pass", None)
        rootverify = webhooks.pop("ssl_verify", None)

        for ntype in [notification_type, "general"]:
            if ntype in webhooks:
                webhook = webhooks[ntype]
                rc = do_notify_webhook_type(
                    webhook=webhook,
                    user=webhook.pop("webhook_user", rootuser),
                    pw=webhook.pop("webhook_pass", rootpw),
                    verify=webhook.pop("ssl_verify", rootverify),
                    subvars=subvars,
                    payload=payload,
                )

    logger.debug(
        "warning: notification generated, but no matching webhook could be found in config to send it to - dropping notification"
    )
    return False


def do_notify_webhook_type(**kwargs):
    webhook = kwargs["webhook"]
    user = kwargs["user"]
    pw = kwargs["pw"]
    verify = kwargs["verify"]
    subvars = kwargs["subvars"]
    payload = kwargs["payload"]

    if not user and not pw:
        auth = None
    else:
        auth = (user, pw)

    url = webhook["url"]

    if not url:
        raise Exception("Cannot send webhook, no URL configured")

    for subkey, subval in subvars:
        url = url.replace(subkey, subval)

    try:
        logger.info("webhook post: " + str(url) + " : " + payload)
        headers = {"Content-Type": "application/json"}
        result = http.anchy_post(
            url, data=payload, auth=auth, timeout=2.0, verify=verify, headers=headers
        )
        logger.info("webhook response: " + str(result))
        return result
    except Exception as err:
        raise Exception(
            "failed to post notification to webhook - exception: " + str(err)
        )
