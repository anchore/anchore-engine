import re

from anchore_engine.apis.authorization import (
    get_authorizer,
    ActionBoundPermission,
    RequestingAccountValue,
    Permission,
)
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.configuration.localconfig import (
    GLOBAL_RESOURCE_DOMAIN,
    ADMIN_ACCOUNT_NAME,
)

authorizer = get_authorizer()

digest_regex = re.compile("^sha256:[abcdef0-9]+$")


def handle_proxy_response(resp):
    if issubclass(Exception, resp.__class__):
        if hasattr(resp, "httpcode"):
            return make_response_error(resp, in_httpcode=resp.httpcode), resp.httpcode
        else:
            return make_response_error(resp, in_httpcode=500), 500
    else:
        return resp, 200


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_archives():
    """
    GET /archives

    :return: JSON object for archive summary
    """

    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.list_archives())
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_analysis_archive_rules(system_global=True):
    """
    GET /archives/rules

    :return:
    """

    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(
            client.list_analysis_archive_rules(system_global=system_global)
        )
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def create_analysis_archive_rule(rule):
    """
    POST /archives/rules

    :param rule: the rule's json object definition
    :return:
    """

    # Permission check on the system_global field, only admins
    if rule.get("system_global"):
        perm = Permission(GLOBAL_RESOURCE_DOMAIN, "createArchiveTransitionRule", "*")

        # Will raise exception if unauthorized
        authorizer.authorize(ApiRequestContextProxy.identity(), [perm])

    # Validation for max_images_per_account
    if (
        not rule.get("system_global")
        and rule.get("max_images_per_account", None) is not None
    ):
        raise BadRequest(
            "Cannot set max_images_per_account on a rule that isn't system_global", {}
        )

    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.add_analysis_archive_rule(rule))
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_analysis_archive_rule(ruleId):
    """

    DELETE /archives/rules/{ruleId}

    :param ruleId:
    :return:
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        resp1 = handle_proxy_response(client.delete_analysis_archive_rule(ruleId))

        if resp1[1] == 404 and ApiRequestContextProxy.namespace() != ADMIN_ACCOUNT_NAME:
            # Yes, this is a bit ugly
            # Get the rule, check if a global rule and adjust error code appropriately
            try:
                c2 = internal_client_for(CatalogClient, ADMIN_ACCOUNT_NAME)
                r2 = c2.get_analysis_archive_rule(ruleId)
                if r2 and r2.get("system_global", False):
                    return (
                        make_response_error(
                            "Non-admins cannot modify/delete system global rules",
                            in_httpcode=403,
                        ),
                        403,
                    )
            except Exception as ex:
                pass
        return resp1

    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_analysis_archive_rule(ruleId):
    """

    GET /archives/rules/{ruleId}

    :param ruleId:
    :return:
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        resp1 = handle_proxy_response(client.get_analysis_archive_rule(ruleId))

        if resp1[1] == 404 and ApiRequestContextProxy.namespace() != ADMIN_ACCOUNT_NAME:
            # Yes, this is a bit ugly
            # Get the rule, check if a global rule
            try:
                c2 = internal_client_for(CatalogClient, ADMIN_ACCOUNT_NAME)
                r2 = handle_proxy_response(c2.get_analysis_archive_rule(ruleId))
                if r2 and r2[1] == 200 and r2[0].get("system_global", False):
                    # Allow it
                    return handle_proxy_response(r2)
            except Exception as ex:
                pass
        return resp1
    except Exception as ex:
        return handle_proxy_response(ex)


# @authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
# def get_analysis_archive_rule_history(ruleId):
#     """
#
#     GET /archives/rules/{ruleId}/history
#
#     :param ruleId:
#     :return: list of events for the rule
#     """
#     client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
#     try:
#         resp1 = handle_proxy_response(client.get_analysis_archive_rule_history(ruleId))
#         if resp1[1] == 404 and ApiRequestContextProxy.namespace() != ADMIN_ACCOUNT_NAME:
#             # Yes, this is a bit ugly
#             # Get the rule, check if a global rule and adjust error code appropriately
#             try:
#                 c2 = internal_client_for(CatalogClient, ADMIN_ACCOUNT_NAME)
#                 r2 = handle_proxy_response(c2.get_analysis_archive_rule(ruleId))
#                 if r2 and r2[1] == 200 and r2[0].get('system_global', False):
#                     return make_response_error('Non-admins cannot modify/delete system global rules', in_httpcode=403), 403
#             except Exception as ex:
#                 pass
#         return resp1
#     except Exception as ex:
#         return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def list_analysis_archive():
    """
    GET /archives/images

    :return: array of archivedimage json objects
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.list_archived_analyses())
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def archive_image_analysis(imageReferences):
    """
    POST /archives/images

    :param imageReferences: list of json object that reference images to archive
    :return:
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.archive_analyses(imageReferences))
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_archived_analysis(imageDigest):
    """
    GET /archives/images/{imageDigest}

    :param imageDigest:
    :return:
    """

    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.get_archived_analysis(imageDigest))
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def delete_archived_analysis(imageDigest):
    """
    DELETE /archives/images/{imageDigest}

    :param imageDigest:
    :return:
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.delete_archived_analysis(imageDigest))
    except Exception as e:
        return handle_proxy_response(e)
