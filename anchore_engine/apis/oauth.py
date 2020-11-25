from yosai.core.authc.authc import UsernamePasswordToken
import time
from anchore_engine.configuration import localconfig
from anchore_engine.subsys import logger
from anchore_engine.db import session_scope, get_session
from anchore_engine.db.entities.identity import OAuth2Client, OAuth2Token
from authlib.flask.oauth2.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from anchore_engine.apis.authorization import get_authorizer
from anchore_engine.auth.oauth import token_manager
from anchore_engine.configuration.localconfig import (
    OauthNotConfiguredError,
    InvalidOauthConfigurationError,
)


class User(object):
    def __init__(self, id):
        self._id = id
        self.username = id

    def get_user_id(self):
        return self._id


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    """
    Login via username password. Disabling client auth itself. Resource owner creds are sufficient.

    """

    TOKEN_ENDPOINT_AUTH_METHODS = ["none"]

    def authenticate_user(self, username, password):
        try:
            authc_token = UsernamePasswordToken(
                username=username, password=password, remember_me=False
            )

            authorizer = get_authorizer()
            identity = authorizer.inline_authz([], authc_token=authc_token)
            # Use the user's uuid as the username/subject for the token to avoid name conflicts over time
            if identity is None:
                raise Exception("Unknown user")
            else:
                return User(identity.user_uuid)
        except:
            logger.debug_exception("Error authenticating")
            raise Exception("User authentication failed")


def generate_token(client, grant_type, user, scope):
    tok_mgr = token_manager()
    return str(tok_mgr.generate_token(user.username), "utf-8")


def init_oauth(app, grant_types, expiration_config):
    """
    Configure the oauth routes and handlers via authlib
    :return:
    """
    logger.debug("Initializing oauth routes")
    try:
        tok_mgr = token_manager()
        logger.info("Initialized the token manager")
    except OauthNotConfiguredError:
        logger.info("OAuth support not configured, cannot initialize it")
        return None
    except InvalidOauthConfigurationError:
        logger.error("OAuth has invalid configuration, cannot initialize it")
        raise

    def query_client(client_id):
        db = get_session()
        c = db.query(OAuth2Client).filter_by(client_id=client_id).first()
        return c

    def do_not_save_token(token, request):
        return None

    # Don't use this (yet), due to token signing that allows system to verify without persistence
    def save_token(token, request):
        try:
            if request.user:
                user_id = request.user.username
            else:
                user_id = None

            client = request.client
            tok = OAuth2Token(client_id=client.client_id, user_id=user_id, **token)

            db = get_session()
            db.add(tok)
            db.commit()
        except:
            logger.exception("Exception saving token")
            raise

    try:
        # Initialize an anonymous client record
        with session_scope() as db:
            f = db.query(OAuth2Client).filter_by(client_id="anonymous").first()
            if not f:
                c = OAuth2Client()
                c.client_id = "anonymous"
                c.user_id = None
                c.client_secret = None
                c.issued_at = time.time() - 100
                c.expires_at = time.time() + 1000
                c.grant_type = "password"
                c.token_endpoint_auth_method = "none"
                c.client_name = "anonymous"
                db.add(c)
    except Exception as e:
        logger.debug("Default client record init failed: {}".format(e))

    app.config["OAUTH2_JWT_ENABLED"] = True
    app.config["OAUTH2_ACCESS_TOKEN_GENERATOR"] = generate_token
    app.config["OAUTH2_REFRESH_TOKEN_GENERATOR"] = False

    # Only the password grant type is used, others can stay defaults
    app.config["OAUTH2_TOKEN_EXPIRES_IN"] = expiration_config

    app.config["OAUTH2_JWT_KEY"] = tok_mgr.default_issuer().signing_key
    app.config["OAUTH2_JWT_ISS"] = tok_mgr.default_issuer().issuer
    app.config["OAUTH2_JWT_ALG"] = tok_mgr.default_issuer().signing_alg

    authz = AuthorizationServer(
        app, query_client=query_client, save_token=do_not_save_token
    )
    # Support only the password grant for now
    for grant in grant_types:
        logger.debug(
            "Registering oauth grant handler: {}".format(
                getattr(grant, "GRANT_TYPE", "unknown")
            )
        )
        authz.register_grant(grant)

    logger.debug("Oauth init complete")
    return authz
