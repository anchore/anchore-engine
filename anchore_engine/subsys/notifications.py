import json
import os
import subprocess
import tempfile

from anchore_engine.clients import http
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger


def make_notification(user_record, subscription_type, notification):
    ret = {}
    try:
        payload_data = {
            'notification_user': user_record['userId'],
            'notification_user_email': user_record['email'],
            'notification_type': subscription_type,
            'notification_payload': notification
        }
        json.dumps(payload_data)
        ret = payload_data
    except Exception as err:
        raise Exception("cannot prepare notification - exception: " + str(err))

    return(ret)

def notify(user_record, notification):
    #notification_modes = ['email', 'webhook']
    notification_modes = ['webhook']

    logger.debug("sending notification: " + json.dumps(notification, indent=4))
    for notification_mode in notification_modes:
        if notification_mode == 'email':
            rc = do_notify_email(user_record, notification)
        elif notification_mode == 'webhook':
            rc = do_notify_webhook(user_record, notification)

    return(True)

def do_notify_webhook(user_record, notification):
    logger.spew("webhook notify user: " + json.dumps(user_record, indent=4))
    logger.debug("webhook notify user: " + json.dumps(notification, indent=4))

    notification_type = notification['data']['notification_type']
    user = pw = None
    subvars = [('<userId>', user_record['userId']), ('<notification_type>', notification_type)]

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
                    result = http.anchy_post(url, data=payload, auth=auth, timeout=2.0, verify=verify)
                    logger.debug("webhook response: " + str(result))
                    return(True)
                except Exception as err:
                    raise Exception("failed to post notification to webhook - exception: " + str(err))
            
    logger.debug("warning: notification generated, but no matching webhook could be found in config to send it to - dropping notification")
    return(False)

def do_notify_email(user_record, notification):
    try:
        userId = user_record['userId']
        email = user_record['email']

        thefile = None
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=False, suffix=".json") as OFH:
            thefile = OFH.name
            OFH.write(json.dumps(notification, indent=4))

        echocmd = subprocess.Popen(("echo", "policy update for image has been detected"), stdout=subprocess.PIPE)
        cmd = ['mail', '-r', 'anchore-engine-notifications@anchore', '-s', '"anchore notification"', '-a', thefile, email]
        sout = subprocess.check_output(cmd, stdin=echocmd.stdout)
        echocmd.wait()

        if thefile and os.path.exists(thefile):
            os.remove(thefile)
    except Exception as err:
        raise err

    return(True)
