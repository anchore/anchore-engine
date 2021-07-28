import anchore_engine.apis
import anchore_engine.common.helpers
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services import internal_client_for
from flask import request
from anchore_engine.apis.authorization import (
    get_authorizer,
    RequestingAccountValue,
    ActionBoundPermission,
)
from anchore_engine.subsys.events import EventBase
from anchore_engine.subsys import logger

import anchore_engine.common

authorizer = get_authorizer()


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_events(
    source_servicename=None,
    source_hostid=None,
    event_type=None,
    resource_type=None,
    resource_id=None,
    level=None,
    since=None,
    before=None,
    page=None,
    limit=None,
):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500
    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object = client.get_events(
            source_servicename=source_servicename,
            source_hostid=source_hostid,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            level=level,
            since=since,
            before=before,
            page=page,
            limit=limit,
        )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_events(before=None, since=None, level=None):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object = client.delete_events(since=since, before=before, level=level)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_event(eventId):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])
        return_object = client.get_event(eventId)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_event(eventId):
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    try:
        client = internal_client_for(CatalogClient, request_inputs["userId"])

        return_object = client.delete_event(eventId)
        if return_object:
            httpcode = 200
            return_object = None
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode


def _event_to_msg(event_cls: EventBase):
    """
    Convert the type class into a description message

    :param event_cls:
    :return:
    """
    return {
        "name": event_cls.__event_type__,
        "type": event_cls.fq_event_type(),
        "message": event_cls.__message__,
        "resource_type": event_cls.__resource_type__,
    }


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_event_types():
    request_inputs = anchore_engine.apis.do_request_prep(request, default_params={})
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    bodycontent = request_inputs["bodycontent"]
    params = request_inputs["params"]

    return_object = {}
    httpcode = 500
    try:
        resp = {}  # use dict first, then will convert to list
        for evnt in EventBase.registered_events():
            if evnt.__category__.name not in resp:
                resp[evnt.__category__.name] = {
                    "name": evnt.__category__.name,
                    "description": evnt.__category__.description,
                    "subcategories": {},
                }

            subcats = resp[evnt.__category__.name]["subcategories"]

            if evnt.__subcategory__.name not in subcats:
                subcats[evnt.__subcategory__.name] = {
                    "name": evnt.__subcategory__.name,
                    "description": evnt.__subcategory__.description,
                    "events": [_event_to_msg(evnt)],
                }
            else:
                subcats[evnt.__subcategory__.name]["events"].append(_event_to_msg(evnt))

        # Flatten back into lists
        return_object = sorted(resp.values(), key=lambda x: x["name"])
        for cat in return_object:
            cat["subcategories"] = sorted(
                cat["subcategories"].values(), key=lambda x: x["name"]
            )

        httpcode = 200
    except Exception as err:
        logger.debug_exception("Error listing types")
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )
        httpcode = return_object["httpcode"]

    return return_object, httpcode
