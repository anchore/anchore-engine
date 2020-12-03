from connexion import request
from werkzeug.datastructures import ImmutableMultiDict


from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.authorization import get_authorizer
import logging as logger
from anchore_engine.auth.oauth import token_manager
from anchore_engine.apis.exceptions import AccessDeniedError


authorizer = get_authorizer()


def get_oauth_token(
    grant_type="password", username=None, password=None, client_id="anonymous"
):
    """
    POST /oauth/token

    Requires the resource-owners credentials in the Authorization Header.

    This is a bit of a mix of the ResourceOwnerPasswordGrant flow and the ImplicitGrant flow since
    this function will populate the necessary fields to perform a password grant if the Authorization
    header is set and no content body is provided

    Note: the parameters above are embedded within the connexion request object, but must be specified in the
    method signature in order for connexion to route the request to this method. So it may appear that they are unused,
    but have no fear, they are!

    :return:
    """

    # Short-circuit if no oauth/token configured
    try:
        tok_mgr = token_manager()
        authz = ApiRequestContextProxy.get_service()._oauth_app
    except Exception as e:
        raise AccessDeniedError("Oauth not enabled in configuration", detail={})

    # Add some default properties if not set in the request
    try:
        if request.content_length == 0 or not request.form:
            logger.debug("Handling converting empty body into form-based grant request")

            if not request.data and not request.form:
                setattr(
                    request,
                    "form",
                    ImmutableMultiDict(
                        [
                            ("username", request.authorization.username),
                            ("password", request.authorization.password),
                            ("grant_type", "password"),
                            ("client_id", "anonymous"),
                        ]
                    ),
                )

        resp = authz.create_token_response()
        logger.debug("Token resp: {}".format(resp))
        return resp
    except:
        logger.exception("Error authenticating")
        raise
