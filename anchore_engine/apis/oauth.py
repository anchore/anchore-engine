import copy
import time

from authlib.integrations.flask_oauth2.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from yosai.core.authc.authc import UsernamePasswordToken

from anchore_engine.apis.authorization import get_authorizer
from anchore_engine.auth.oauth import token_manager
from anchore_engine.configuration.localconfig import (
    InvalidOauthConfigurationError,
    OauthNotConfiguredError,
)
from anchore_engine.db import get_session, session_scope
from anchore_engine.db.entities.identity import OAuth2Client, OAuth2Token
from anchore_engine.subsys import logger

# System uses an anonymous client, so that users do not have to register specific clients
# This could be extended in the future to add client registration and auth support in OAuth2 flows

ANONYMOUS_CLIENT_ID = "anonymous"
CLIENT_GRANT_KEY = "grant_types"


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

    :param app:
    :param grant_types:
    :param expiration_config:
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
        expected_metadata = {
            "token_endpoint_auth_method": "none",  # This should be a function of the grant type input but all of our types are this currently
            "client_name": "anonymous",
            "grant_types": [grant.GRANT_TYPE for grant in grant_types],
        }

        # Initialize an anonymous client record
        with session_scope() as db:
            found = (
                db.query(OAuth2Client)
                .filter_by(client_id=ANONYMOUS_CLIENT_ID)
                .one_or_none()
            )

            logger.info("Creating new oauth client record for %s", ANONYMOUS_CLIENT_ID)
            to_merge = OAuth2Client()
            to_merge.client_id = ANONYMOUS_CLIENT_ID
            to_merge.user_id = None
            to_merge.client_secret = None
            # These are no-ops effectively since the client isn't authenticated itself
            to_merge.client_id_issued_at = time.time() - 100
            to_merge.client_secret_expires_at = time.time() + 1000
            to_merge.set_client_metadata(
                {
                    "token_endpoint_auth_method": "none",  # This should be a function of the grant type input but all of our types are this currently
                    "client_name": ANONYMOUS_CLIENT_ID,
                    "grant_types": [grant.GRANT_TYPE for grant in grant_types],
                }
            )

            merged = setup_oauth_client(found, to_merge)
            merged = db.merge(merged)
            logger.info(
                "Initializing db record for oauth client %s with grants %s",
                merged.client_id,
                merged.client_metadata.get("grant_types"),
            )
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


def merge_client_metadata(found_meta: dict, expected_metadata: dict) -> dict:
    """
    Merge the client metadata from what is found and what is needed to create a single metadata record.

    This includes a merge of the grant_types via a union operation, and replacement of any conflicting keys in the found_meta with values from expected_meta.

    :param found_meta: The metadata dict from the existing record
    :param expected_metadata: The metadata dict to merge in
    :return: dict of merged information
    """

    # Merge the new grant types in, defaulting to empty grant lists if not found
    if found_meta is None:
        found_meta = {}

    found_grants = set(found_meta.get(CLIENT_GRANT_KEY, []))
    new_grants = set(expected_metadata.get(CLIENT_GRANT_KEY, []))
    new_grants = new_grants.union(found_grants)

    # Create a copy to ensure we don't modify the state of anything passed in
    merged = copy.copy(found_meta)

    # Merge in the non-grant keys
    merged.update(expected_metadata)
    merged[CLIENT_GRANT_KEY] = list(new_grants)

    return merged


def setup_oauth_client(found: OAuth2Client, to_merge: OAuth2Client) -> OAuth2Client:
    """
    Evaluate and merge the two records into a single record with the correct grants

    :param found:
    :param to_add_merge:
    :return:
    """
    if found:
        logger.info("Checking existing client record for %s", found.client_id)
        logger.info("Checking client record %s", found.client_metadata)

        # Ensure the client record has the right set of grant types, not one grant per client, since we have a single client_id
        found_meta = found.client_metadata
        merged = merge_client_metadata(found_meta, to_merge.client_metadata)

        # Try a simple set first, if it doesn't work, the update the dict content directly. This is necessary
        # due to the implementation of the client_metadata property
        found.set_client_metadata(merged)

        # Have to clear because the "set_client_metadata" doesn't work properly once the data is initialized.
        # So use an in-place update, and the 'merged' state will replace all the state.
        if found.client_metadata != merged:
            found.client_metadata.clear()
            found.client_metadata.update(merged)

        logger.info(
            "Updated %s OAuth client record with grants %s",
            found.client_id,
            found.client_metadata.get("grant_types"),
        )
        return found
    else:
        return to_merge
