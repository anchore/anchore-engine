import json

from connexion import request

# anchore modules
import anchore_engine.apis
import anchore_engine.common
import anchore_engine.common.helpers
from anchore_engine.configuration import localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine import db
from anchore_engine.apis.authorization import get_authorizer, ActionBoundPermission
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.common.errors import AnchoreError
from anchore_engine.configuration.localconfig import GLOBAL_RESOURCE_DOMAIN
from anchore_engine.subsys import logger, notifications
from anchore_engine.subsys.identities import manager_factory

authorizer = get_authorizer()


def make_response_service(user_auth, service_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        for k in [
            "hostid",
            "version",
            "base_url",
            "status",
            "status_message",
            "servicename",
        ]:
            ret[k] = service_record[k]
        if "short_description" in service_record:
            try:
                ret["service_detail"] = json.loads(service_record["short_description"])
            except:
                ret["service_detail"] = str(service_record["short_description"])

    except Exception as err:
        raise Exception("failed to format service response: " + str(err))

    # global items to filter out
    for removekey in ["record_state_val", "record_state_key"]:
        ret.pop(removekey, None)

    return ret


def ping():
    """
    GET /

    :return: 200 status with api version string
    """
    return ApiRequestContextProxy.get_service().__service_api_version__, 200


@authorizer.requires([])  # Any authenticated user
def get_status():
    """
    GET /status

    :return: service status object
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})

    return_object = {}
    httpcode = 500

    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([])
def get_service_detail():
    """
    GET /system

    :return: list of service details
    """

    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]

    httpcode = 500
    service_detail = {}

    try:
        try:
            try:
                service_detail["service_states"] = []
                try:
                    up_services = {}
                    client = internal_client_for(
                        CatalogClient, request_inputs["userId"]
                    )
                    service_records = client.get_service()
                    for service in service_records:
                        el = make_response_service(user_auth, service, params)

                        service_detail["service_states"].append(el)

                        if el["servicename"] not in up_services:
                            up_services[el["servicename"]] = 0

                        if el["status"]:
                            up_services[el["servicename"]] += 1

                except Exception as err:
                    pass

                httpcode = 200

            except Exception as err:
                return_object = anchore_engine.common.helpers.make_response_error(
                    err, in_httpcode=httpcode
                )
                httpcode = return_object["httpcode"]
        except:
            service_detail = {}

        return_object = service_detail
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def list_services():
    """
    GET /system/services

    :param request_inputs:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        service_records = client.get_service()
        for service_record in service_records:
            return_object.append(
                make_response_service(user_auth, service_record, params)
            )

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def get_services_by_name(servicename):
    """
    GET /system/services/<servicename>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
        service_records = client.get_service(servicename=servicename)
        for service_record in service_records:
            return_object.append(
                make_response_service(user_auth, service_record, params)
            )

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def get_services_by_name_and_host(servicename, hostid):
    """
    GET /system/services/<servicename>/<hostid>

    :param request_inputs:
    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    params = request_inputs["params"]

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
        service_records = client.get_service(servicename=servicename, hostid=hostid)
        for service_record in service_records:
            return_object.append(
                make_response_service(user_auth, service_record, params)
            )

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def delete_service(servicename, hostid):
    """
    DELETE /system/services/<servicename>/<hostid>

    :param servicename:
    :param hostid:
    :return:
    """
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]

    return_object = []
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object = client.delete_service(servicename=servicename, hostid=hostid)
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([])
def get_system_feeds():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        # do the p.e. feed get call
        return_object = p_client.list_feeds(include_counts=True)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def post_system_feeds(flush=False):
    request_inputs = anchore_engine.apis.do_request_prep(
        request, default_params={"flush": flush}
    )

    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        # do the p.e. feed post call
        return_object = p_client.sync_feeds(force_flush=flush)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def toggle_feed_enabled(feed, enabled):
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        return_object = p_client.toggle_feed_enabled(feed, enabled)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def toggle_group_enabled(feed, group, enabled):
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        return_object = p_client.toggle_feed_group_enabled(feed, group, enabled)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def delete_feed(feed):
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        return_object = p_client.delete_feed(feed)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=GLOBAL_RESOURCE_DOMAIN)])
def delete_feed_group(feed, group):
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        return_object = p_client.delete_feed_group(feed, group)
        if return_object is not None:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([])
def describe_policy():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = []
    httpcode = 500
    try:
        p_client = internal_client_for(
            PolicyEngineClient, userId=ApiRequestContextProxy.namespace()
        )
        return_object = p_client.describe_policy()
        if return_object:
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([])
def describe_error_codes():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    return_object = []
    httpcode = 500
    try:
        for e in AnchoreError:
            el = {
                "name": e.name,
                "description": e.value,
            }
            return_object.append(el)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires_account(with_names=[localconfig.ADMIN_ACCOUNT_NAME])
def test_webhook(webhook_type="general", notification_type="tag_update"):
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
        if "webhooks" in localconfig:
            webhooks.update(localconfig["webhooks"])

        if not webhooks:
            httpcode = 400
            return_object = anchore_engine.common.helpers.make_response_error(
                "Webhooks Configuration not found", in_httpcode=httpcode
            )
            return return_object, httpcode

        webhook = webhooks[webhook_type]
        if not webhook:
            httpcode = 400
            return_object = anchore_engine.common.helpers.make_response_error(
                "No Webhook Configuration found for type={}".format(webhook_type),
                in_httpcode=httpcode,
            )
            return return_object, httpcode

        return send_test_notification(
            webhooks, webhook, request_inputs, webhook_type, notification_type
        )
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def get_test_notification(notification_type, request_inputs):
    """
    Build a test notification payload (format should mirror what's returned by get_webhook_schema)
    :param notification_type: type of notification to send
    :param request_inputs: metadata from request to test webhook
    """

    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        notification = notifications.Notification(
            notification_type,
            request_inputs["userId"],
            mgr.get_account(request_inputs["userId"])["email"],
        )

    logger.debug("Test Notification JSON: {}".format(notification.to_json()))

    return notification


def send_test_notification(
    webhooks, webhook, request_inputs, webhook_type, notification_type
):
    """
    This Method actually gathers all the parameters needed for notifications to actually send the webhook

    :param webhooks: webhooks loaded from localconfig
    :param webhook: the webhook object for webhook_type
    :param request_inputs: the request inputs (used to resolve userId)
    :param webhook_type: webhook type to send (used to build payload)
    :return: result of webhook and http code (200 if successful, 500 if we fail to build test notification or payload
    """
    httpcode = 500
    rootuser = webhooks.pop("webhook_user", None)
    rootpw = webhooks.pop("webhook_pass", None)
    rootverify = webhooks.pop("ssl_verify", None)

    subvars = [("<userId>", request_inputs["userId"]), ("<notification_type>", "test")]

    try:
        notification = get_test_notification(notification_type, request_inputs)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        return return_object, httpcode

    logger.debug("build payload: {}".format(notification.to_json()))
    try:
        payload = notification.to_json()
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        return return_object, httpcode

    return (
        notifications.do_notify_webhook_type(
            webhook=webhook,
            user=webhook.pop("webhook_user", rootuser),
            pw=webhook.pop("webhook_pass", rootpw),
            verify=webhook.pop("ssl_verify", rootverify),
            subvars=subvars,
            payload=payload,
        ),
        200,
    )
