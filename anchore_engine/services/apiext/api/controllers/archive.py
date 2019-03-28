import re
from anchore_engine.subsys import logger
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.authorization import get_authorizer, ActionBoundPermission, RequestingAccountValue
from anchore_engine.common.helpers import make_response_error
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient

authorizer = get_authorizer()

digest_regex = re.compile('^sha256:[abcdef0-9]+$')


def handle_proxy_response(resp):
    if issubclass(Exception, resp.__class__):
        if hasattr(resp, 'httpcode'):
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
def list_analysis_archive_rules():
    """
    GET /archives/rules

    :return:
    """

    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.list_analysis_archive_rules())
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def create_analysis_archive_rule(rule):
    """
    POST /archives/rules

    :param rule: the rule's json object definition
    :return:
    """

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
        return handle_proxy_response(client.delete_analysis_archive_rule(ruleId))
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
        return handle_proxy_response(client.get_analysis_archive_rule(ruleId))
    except Exception as ex:
        return handle_proxy_response(ex)


@authorizer.requires([ActionBoundPermission(domain=RequestingAccountValue())])
def get_analysis_archive_rule_history(ruleId):
    """

    GET /archives/rules/{ruleId}/history

    :param ruleId:
    :return: list of events for the rule
    """
    client = internal_client_for(CatalogClient, ApiRequestContextProxy.namespace())
    try:
        return handle_proxy_response(client.get_analysis_archive_rule_history(ruleId))
    except Exception as ex:
        return handle_proxy_response(ex)


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
