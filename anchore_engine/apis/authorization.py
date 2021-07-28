"""
API Authorization handlers and functions for use in API processing

"""
import enum
import json
from abc import abstractmethod, ABC
import anchore_engine
from collections import namedtuple
from anchore_engine.subsys import logger
from connexion import request as request_proxy
from flask import Response
from anchore_engine.apis.context import ApiRequestContextProxy
from yosai.core import Yosai, exceptions as auth_exceptions, UsernamePasswordToken
from yosai.core.authc.authc import token_info
from yosai.core.authc.abcs import AuthenticationToken
from anchore_engine.db import session_scope, AccountTypes, AccountStates
import pkg_resources
import functools
from anchore_engine.common.helpers import make_response_error
from anchore_engine.apis.authentication import idp_factory, IdentityContext
from anchore_engine.apis.exceptions import AnchoreApiError
from threading import RLock
from anchore_engine.subsys.auth.realms import UsernamePasswordRealm, ExternalAuthorizer
from anchore_engine.configuration import localconfig
from anchore_engine.subsys.auth.stores.verifier import JwtToken

# Global authorizer configured
_global_authorizer = None

INTERNAL_SERVICE_ALLOWED = [AccountTypes.admin, AccountTypes.service]


# ToDo: rename this to AccessDeniedError
class UnauthorizedError(Exception):
    def __init__(self, required_permissions):
        if type(required_permissions) != list:
            required_permissions = [required_permissions]

        perm_str = ",".join(
            "domain={} action={} target={}".format(
                perm.domain, perm.action, "*" if perm.target is None else perm.target
            )
            for perm in required_permissions
        )
        super(UnauthorizedError, self).__init__(
            "Not authorized. Requires permissions: {}".format(perm_str)
        )
        self.required_permissions = required_permissions


class AccountStateError(UnauthorizedError):
    def __init__(self, account):
        super(AccountStateError, self).__init__([])
        self.msg = "Not authorized. Account {} not enabled.".format(account)

    def __str__(self):
        return self.msg


class UnauthorizedAccountError(Exception):
    def __init__(self, account_types):
        super(UnauthorizedAccountError, self).__init__(
            "Not authorized. Requires callers account of type {}".format(account_types)
        )


class UnauthenticatedError(Exception):
    pass


Permission = namedtuple("Permission", ["domain", "action", "target"])


class ActionBoundPermission(object):
    def __init__(self, domain, target="*"):
        self.domain = domain
        self.action = OperationActionLookup(action_provider)
        self.target = target


def action_provider(op_id):
    """
    Lazy lookup of the action associated with the operation id via the request context reference
    to the parent service, which provides the map of ops->actions (via the swagger doc)
    :param op_id:
    :return:
    """
    return ApiRequestContextProxy.get_service().action_for_operation(op_id)


class LazyBoundValue(ABC):
    """
    A generic domain handler that supports lazy binding and injection
    """

    def __init__(self, value=None):
        self._value = value

    def bind(self, operation: callable, kwargs=None):
        """
        Bind the actual value for the authz domain if applicable
        :return:
        """
        pass

    @property
    def value(self):
        """
        Retrieves the value of the domain
        :return:
        """
        return self._value


class FunctionInjectedValue(LazyBoundValue):
    def __init__(self, load_fn):
        super().__init__(None)
        self.loader = load_fn

    def bind(self, operation, kwargs=None):
        self._value = self.loader()


class RequestingAccountValue(FunctionInjectedValue):
    def __init__(self):
        super().__init__(lambda: ApiRequestContextProxy.namespace())


class ParameterBoundValue(LazyBoundValue):
    def __init__(self, parameter_name, default_value=None):
        super().__init__(default_value)
        self.param_name = parameter_name

    def bind(self, operation, kwargs=None):
        self._value = kwargs.get(self.param_name) if kwargs else self._value


class OperationActionLookup(FunctionInjectedValue):
    def bind(self, operation: callable, kwargs=None):
        fq_operation_id = operation.__module__ + "." + operation.__name__
        self._value = self.loader(fq_operation_id)


class NotificationTypes(enum.Enum):
    domain_created = "domain_created"
    domain_deleted = "domain_deleted"
    principal_created = "principal_created"
    principal_deleted = "principal_deleted"


class AuthorizationHandler(ABC):
    def __init__(self, identity_provider_factory):
        self._idp_factory = identity_provider_factory

    @abstractmethod
    def load(self, configuration):
        """
        Deferred loader for the handler to avoid constructor issues

        :param configuration:
        :return:
        """

        pass

    @abstractmethod
    def authorize(self, identity: IdentityContext, permission_list):
        """
        Authorize the described permissions (all must pass) for the identity
        Where domain = account | 'system'
        action_type in ActionTypes


        :param identity: IdentityContext object for the entity to authorize
        :param permission_list: list of Permission objects that must all be allowed
        :return:
        """
        pass

    @abstractmethod
    def authenticate(self, request):
        """
        Authenticate a request (wsgi/flask), perform any login/auth and return the authenticated account, username tuple
        :return: (account, username)
        """
        pass

    def check_permissions(self, permission_s):
        """

        :param permission_s: List of permission tuples (domain, action, target) that must all be verified
        :return:
        """
        pass

    @abstractmethod
    def requires(self, permission_s: list):
        pass

    @abstractmethod
    def requires_account(self, with_names=None, with_types=None):
        """
        Requires a specific role name. This is typically use for internal services where the role name is the account name of the caller
        :param with_types: a list of AccountType objects that define the acceptable account types
        :return:
        """
        pass

    @abstractmethod
    def notify(self, notification_type, notification_value):
        pass

    @abstractmethod
    def healthcheck(self):
        """
        Function to invoke to determine if handler is healthy and able to process requests
        :return:
        """
        pass

    @abstractmethod
    def inline_authz(self, permission_s: list, authc_token: AuthenticationToken = None):
        """
        Function to invoke an inline authz, similar to requires_* functions but non-decorator.
        :param permission_s:
        :param authc_token: An AuthenticationToken object to authenticate with. If None, the authc will use the request context
        :return:
        """
        pass


class DbAuthorizationHandler(AuthorizationHandler):
    """
    Default authorization handler for service apis.

    """

    _yosai = None
    _config_lock = RLock()

    def load(self, configuration):
        with DbAuthorizationHandler._config_lock:
            conf_path = pkg_resources.resource_filename(
                anchore_engine.__name__, "conf/default_yosai_settings.yaml"
            )
            DbAuthorizationHandler._yosai = Yosai(file_path=conf_path)
            # Disable sessions, since the APIs are not session-based
            DbAuthorizationHandler._yosai.security_manager.subject_store.session_storage_evaluator.session_storage_enabled = (
                False
            )

            token_info[JwtToken] = {"tier": 1, "cred_type": "jwt"}

    def notify(self, notification_type, notification_value):
        """
        No-Op for the default handler since permissions are ephemeral.
        :param notification_type:
        :param notification_value:
        :return:
        """
        return True

    def healthcheck(self):
        try:
            with session_scope() as session:
                mgr = idp_factory.for_session(session)
                sys_usr = mgr.lookup_user(localconfig.SYSTEM_USERNAME)
                if sys_usr is not None:
                    logger.debug("Healthcheck for native authz handler returning ok")
                    return True
        except Exception as e:
            logger.error(
                "Healthcheck for native authz handler caught exception: {}".format(e)
            )

        return False

    def get_authc_token(self, request):
        authz_header = request.environ.get("HTTP_AUTHORIZATION")
        authc_token = None

        if request.authorization:
            # HTTP Basic/Digest Auth
            authc_token = UsernamePasswordToken(
                username=request.authorization.username,
                password=request.authorization.password,
                remember_me=False,
            )
        elif authz_header:
            # check for bearer auth
            parts = authz_header.split()
            if parts and len(parts) > 1:
                auth_type = parts[0].lower()
                if auth_type in ["bearer", "jwt"]:
                    authc_token = JwtToken(parts[1])

        return authc_token

    def authenticate_token(self, authc_token=None):
        if authc_token:
            subject = Yosai.get_current_subject()
            try:
                subject.login(authc_token)
            except:
                logger.debug_exception("Login failed")
                raise

            user = subject.primary_identifier
            logger.debug("Login complete for user: {}".format(user))
            if isinstance(user, IdentityContext):
                return user
            else:
                # Simple account lookup to ensure the context identity is complete
                try:
                    logger.debug(
                        "Loading identity context from username: {}".format(user)
                    )
                    with session_scope() as db_session:
                        idp = self._idp_factory.for_session(db_session)
                        identity, _ = idp.lookup_user(user)

                        logger.debug("Authc complete for user: {}".format(user))
                        return identity
                except:
                    logger.debug_exception(
                        "Error looking up account for authenticated user"
                    )
                    return None
        else:
            logger.debug("Anon auth complete")
            return IdentityContext(
                username=None,
                user_account=None,
                user_account_type=None,
                user_account_state=None,
            )

    def authenticate(self, request):
        authc_token = self.get_authc_token(request)
        return self.authenticate_token(authc_token)

    def _check_calling_user_account_state(self, identity):
        """
        Raise an exception if the calling identity is a member of a non-enabled account.

        :param identity:
        :return:
        """
        # Do account state check here for authz rather than in the authc path since it's a property of an authenticated user
        if (
            not identity.user_account_state
            or identity.user_account_state != AccountStates.enabled
        ):
            logger.debug("Failing perm check based on account state")
            raise AccountStateError(identity.user_account)

    def _disabled_domains(self, permissions):
        """
        Return the account state of all domains in the permission set. If a domain is the global domain or system domain then it
        is enabled by default. Else, if domain is not found in the account list, it is considered not-enabled.

        :param permissions: list of Permission objects
        :return: list(str) returns a tuple of enabled and non-enable domains from the permissions list
        """

        non_enabled_domains = []

        for p in permissions:
            if p.domain in [
                localconfig.SYSTEM_ACCOUNT_NAME,
                localconfig.GLOBAL_RESOURCE_DOMAIN,
            ]:
                # System and global domains are always enabled
                continue
            else:
                state = self._get_account_state(p.domain)
                if state is None or state != AccountStates.enabled:
                    non_enabled_domains.append(p.domain)

        return list(set(non_enabled_domains))

    def _exec_permission_check(self, subject, permission_list):
        """
        Normalize the permission list and execute the checks

        :param permission_list: list of Permission objects
        :return:
        """
        logger.debug("Checking permission: {}".format(permission_list))
        try:
            stringified_permissions = []
            for perm in permission_list:
                domain = perm.domain if perm.domain else "*"
                action = perm.action if perm.action else "*"
                target = perm.target if perm.target else "*"
                stringified_permissions.append(":".join([domain, action, target]))
            subject.check_permission(stringified_permissions, logical_operator=all)

        except (ValueError, auth_exceptions.UnauthorizedException) as ex:
            raise UnauthorizedError(required_permissions=permission_list)

    def authorize(self, identity: IdentityContext, permission_list):
        subject = Yosai.get_current_subject()
        if subject.primary_identifier != identity:
            logger.debug(
                "Mismatch between subject and provided identity for the authorization. Failing authz"
            )
            raise UnauthorizedError(permission_list)

        # Do account state check here for authz rather than in the authc path since it's a property of an authenticated user
        self._check_calling_user_account_state(identity)

        self._exec_permission_check(subject, permission_list)

        # Check only after the perms check. Match any allowed permissions that use the namespace as the domain for the authz request
        non_enabled_domains = self._disabled_domains(permission_list)

        logger.debug("Found disabled domains found: {}".format(non_enabled_domains))

        # If found domains not enabled and the caller is not a system service or system admin, disallow
        if non_enabled_domains and identity.user_account_type not in [
            AccountTypes.admin,
            AccountTypes.service,
        ]:
            raise AccountStateError(non_enabled_domains[0])

    def _get_account_state(self, account):
        """
        Verify that the namespace is enabled or else the calling identity is a user in the system admin group
        """

        with session_scope() as session:
            identities = idp_factory.for_session(session)
            n = identities.lookup_account(account)
            if n:
                return n["state"]
            else:
                return None

    def _check_account(self, account_name, account_type, with_names, with_types):
        try:
            if type(account_type) == AccountTypes:
                account_type = account_type.value

            if with_types:
                with_types = [
                    x.value if type(x) == AccountTypes else x for x in with_types
                ]

            if (with_names is None or account_name in with_names) and (
                with_types is None or account_type in with_types
            ):
                return True
            else:
                raise UnauthorizedAccountError(
                    account_types=",".join(with_types if with_types else [])
                )
        except UnauthorizedAccountError as ex:
            raise
        except Exception as e:
            logger.exception("Error doing authz: {}".format(e))
            raise UnauthorizedAccountError(
                account_types=",".join(with_types if with_types else [])
            )

    def inline_authz(self, permission_s: list, authc_token: AuthenticationToken = None):
        """
        Non-decorator impl of the @requires() decorator for isolated and inline invocation.
        Returns authenticated user identity on success or raises an exception

        :param permission_s: list of Permission objects
        :param authc_token: optional authc token to use for the authc portion, if omitted or None, the flask request context is used
        :return: IdentityContext object
        """
        try:
            with Yosai.context(self._yosai):
                # Context Manager functions
                try:
                    try:
                        if not authc_token:
                            identity = self.authenticate(request_proxy)
                        else:
                            identity = self.authenticate_token(authc_token)

                        if not identity.username:
                            raise UnauthenticatedError("Authentication Required")

                    except:
                        raise UnauthenticatedError("Authentication Required")

                    ApiRequestContextProxy.set_identity(identity)
                    permissions_final = []

                    # Bind all the permissions as needed
                    for perm in permission_s:
                        domain = perm.domain if perm.domain else "*"
                        action = perm.action if perm.action else "*"
                        target = perm.target if perm.target else "*"
                        permissions_final.append(Permission(domain, action, target))

                    # Do the authz on the bound permissions
                    try:
                        self.authorize(
                            ApiRequestContextProxy.identity(), permissions_final
                        )
                    except UnauthorizedError as ex:
                        raise ex
                    except Exception as e:
                        logger.exception("Error doing authz: {}".format(e))
                        raise UnauthorizedError(permissions_final)

                    return ApiRequestContextProxy.identity()
                finally:
                    # Teardown the request context
                    ApiRequestContextProxy.set_identity(None)
        except UnauthorizedError as ex:
            return make_response_error(str(ex), in_httpcode=403), 403
        except UnauthenticatedError as ex:
            return Response(
                response="Unauthorized",
                status=401,
                headers=[("WWW-Authenticate", 'basic realm="Authentication required"')],
            )
        except AnchoreApiError:
            raise
        except Exception as ex:
            logger.exception("Unexpected exception: {}".format(ex))
            return make_response_error("Internal error", in_httpcode=500), 500

    def requires_account(self, with_names=None, with_types=None):
        """
        :param with_names: list of strings of names any of which is accepted
        :param with_types: list of strings of account types any of which are accepted
        :return:
        """
        if with_names is None and with_types is None:
            raise ValueError("Cannot have None values for both name and type")

        def outer_wrapper(f):
            @functools.wraps(f)
            def inner_wrapper(*args, **kwargs):
                try:
                    with Yosai.context(self._yosai):
                        # Context Manager functions
                        try:
                            try:
                                identity = self.authenticate(request_proxy)
                                if not identity.username:
                                    raise UnauthenticatedError(
                                        "Authentication Required"
                                    )
                            except:
                                raise UnauthenticatedError("Authentication Required")

                            ApiRequestContextProxy.set_identity(identity)

                            if self._check_account(
                                identity.user_account,
                                identity.user_account_type,
                                with_names,
                                with_types,
                            ):
                                return f(*args, **kwargs)
                        finally:
                            # Teardown the request context
                            ApiRequestContextProxy.set_identity(None)

                except UnauthorizedAccountError as ex:
                    return make_response_error(str(ex), in_httpcode=403), 403
                except UnauthenticatedError as ex:
                    return Response(
                        response="Unauthorized",
                        status=401,
                        headers=[
                            (
                                "WWW-Authenticate",
                                'basic realm="Authentication required"',
                            )
                        ],
                    )
                except AnchoreApiError:
                    raise
                except Exception as ex:
                    logger.exception("Unexpected exception: {}".format(ex))
                    return make_response_error("Internal error", in_httpcode=500), 500

            return inner_wrapper

        return outer_wrapper

    def requires(self, permission_s: list):
        """
        Decorator for convenience on access control on API operations

        Empty list for authc only

        :param permission_s: list of Permission objects

        :return:
        """

        def outer_wrapper(f):
            @functools.wraps(f)
            def inner_wrapper(*args, **kwargs):
                try:
                    with Yosai.context(self._yosai):
                        # Context Manager functions
                        try:
                            try:
                                identity = self.authenticate(request_proxy)
                                if not identity.username:
                                    raise UnauthenticatedError(
                                        "Authentication Required"
                                    )
                            except:
                                raise UnauthenticatedError("Authentication Required")

                            ApiRequestContextProxy.set_identity(identity)
                            permissions_final = []

                            # Bind all the permissions as needed
                            for perm in permission_s:
                                domain = perm.domain if perm.domain else "*"
                                action = perm.action if perm.action else "*"
                                target = perm.target if perm.target else "*"

                                if hasattr(domain, "bind"):
                                    domain.bind(operation=f, kwargs=kwargs)
                                    domain = domain.value

                                if hasattr(action, "bind"):
                                    action.bind(operation=f, kwargs=kwargs)
                                    action = action.value

                                if hasattr(target, "bind"):
                                    target.bind(operation=f, kwargs=kwargs)
                                    target = target.value

                                # permissions_final.append(':'.join([domain, action, target]))
                                permissions_final.append(
                                    Permission(domain, action, target)
                                )

                            # Do the authz on the bound permissions
                            try:
                                self.authorize(
                                    ApiRequestContextProxy().identity(),
                                    permissions_final,
                                )
                            except UnauthorizedError as ex:
                                raise ex
                            except Exception as e:
                                logger.exception("Error doing authz: {}".format(e))
                                raise UnauthorizedError(permissions_final)

                            return f(*args, **kwargs)
                        finally:
                            # Teardown the request context
                            ApiRequestContextProxy.set_identity(None)

                except UnauthorizedError as ex:
                    return make_response_error(str(ex), in_httpcode=403), 403
                except UnauthenticatedError as ex:
                    return Response(
                        response="Unauthorized",
                        status=401,
                        headers=[
                            (
                                "WWW-Authenticate",
                                'basic realm="Authentication required"',
                            )
                        ],
                    )
                except AnchoreApiError:
                    raise
                except Exception as ex:
                    logger.exception("Unexpected exception: {}".format(ex))
                    return make_response_error("Internal error", in_httpcode=500), 500

            return inner_wrapper

        return outer_wrapper


class ExternalAuthorizationHandler(DbAuthorizationHandler):
    __external_authorizer__ = None

    def healthcheck(self):
        """
        Raises an exception on failure or returns True on success

        :return:
        """

        internal_check = external_check = False

        try:
            internal_check = super().healthcheck()
        except Exception as e:
            logger.error(
                "Caught exception from admin/native authz check: {}".format(str(e))
            )
            internal_check = False

        try:
            if not self.__external_authorizer__:
                logger.warn(
                    "Attempted health check for external authz handler but no client configured yet"
                )
                return False
            else:
                external_check = self.__external_authorizer__.client.healthcheck()
        except Exception as e:
            logger.error(
                "Healthcheck for external authz handler caught exception: {}".format(e)
            )
            external_check = False

        logger.debug(
            "External authz healthcheck result: internal handler {}, external handler {}".format(
                internal_check, external_check
            )
        )
        if internal_check and external_check:
            return True
        else:
            raise Exception(
                "Internal authz check returned {}, External authz check returned {}".format(
                    internal_check, external_check
                )
            )

    def notify(self, notification_type, notification_value):
        """
        No-Op for the default handler since permissions are ephemeral.
        :param notification_type:
        :param notification_value:
        :return:
        """
        logger.info("Calling notification!")
        retries = 3

        try:
            if not self.__external_authorizer__:
                logger.warn(
                    "Got authz notification type: {} value:{}, but no client configured so nothing to do".format(
                        notification_type, notification_value
                    )
                )
                return True
            else:
                if NotificationTypes.domain_created == notification_type:
                    fn = self.__external_authorizer__.client.initialize_domain
                elif NotificationTypes.domain_deleted == notification_type:
                    fn = self.__external_authorizer__.client.delete_domain
                elif NotificationTypes.principal_created == notification_type:
                    fn = self.__external_authorizer__.client.initialize_principal
                elif NotificationTypes.principal_deleted == notification_type:
                    fn = self.__external_authorizer__.client.delete_principal
                else:
                    fn = None

            if fn is None:
                logger.warn(
                    "Got notification type {} with no handler mapped".format(
                        notification_type
                    )
                )
                return

            err = None
            for i in range(retries):
                try:
                    resp = fn(notification_value)
                    if not resp:
                        logger.warn(
                            "Bad response from authz service, will retry: {}".format(
                                resp
                            )
                        )
                    else:
                        logger.debug("Notification succeeded to authz plugin service")
                        break
                except Exception as ex:
                    err = ex
                    logger.exception(
                        "Error calling {} against authz plugin client".format(
                            fn.__name__
                        )
                    )

            else:
                logger.error(
                    "Could not confirm successful response of authz handler for notification {} with value {}".format(
                        notification_type, notification_value
                    )
                )
                raise Exception(
                    "Error invoking POST /domains on external authz handler: {}".format(
                        str(err) if err else "Retry count exceeded {}".format(retries)
                    )
                )

            return True

        except:
            logger.exception(
                "Notification handler for external authz plugin caught exception and could not complete: {} {}".format(
                    notification_type, notification_type
                )
            )
            raise

    def load(self, configuration):
        with ExternalAuthorizationHandler._config_lock:
            logger.info("Initializing external authz realm")

            self.__external_authorizer__ = ExternalAuthorizer(
                configuration, enabled=True
            )
            UsernamePasswordRealm.__external_authorizer__ = self.__external_authorizer__

            # conf_path = pkg_resources.resource_filename(anchore_engine.__name__, 'conf/external_authz_yosai_settings.yaml')
            conf_path = pkg_resources.resource_filename(
                anchore_engine.__name__, "conf/default_yosai_settings.yaml"
            )
            ExternalAuthorizationHandler._yosai = Yosai(file_path=conf_path)

            # Disable sessions, since the APIs are not session-based
            ExternalAuthorizationHandler._yosai.security_manager.subject_store.session_storage_evaluator.session_storage_enabled = (
                False
            )

            token_info[JwtToken] = {"tier": 1, "cred_type": "jwt"}
            logger.info("External authz handler init complete")


# TODO: address this, and fix it
class InternalServiceAuthorizer(DbAuthorizationHandler):
    """
    Authz Handler optimized for internal services
    """

    def load(self, configuration):
        conf_path = pkg_resources.resource_filename(
            anchore_engine.__name__, "conf/internal_authz_yosai_settings.yaml"
        )
        self.yosai = Yosai(file_path=conf_path)

        # Disable sessions, since the APIs are not session-based
        self.yosai.security_manager.subject_store.session_storage_evaluator.session_storage_enabled = (
            False
        )


def auth_function_factory():
    """
    An auth function factory that returns functions that can be used in before_request() calls to flask for doing
    auth for things like subsystems that Anchore doesn't define each route for
    :param authorizer_fetch_fn:
    :return:
    """

    def do_auth():
        try:
            resp = get_authorizer().inline_authz([])
            if isinstance(resp, IdentityContext):
                return None
            else:
                if resp is not None:
                    if type(resp) == tuple:
                        if type(resp[0]) == dict:
                            return Response(
                                json.dumps(resp[0]),
                                status=resp[1],
                                content_type="application/json",
                            )
                        else:
                            return Response(resp[0], status=resp[1])
                return resp
        except:
            return Response(
                "Unauthorized",
                status=401,
                headers=[("WWW-Authenticate", 'basic realm="Authentication required"')],
            )

    return do_auth


def init_authz_handler(configuration=None):
    global _global_authorizer
    handler_config = configuration.get("authorization_handler")
    if handler_config == "native" or handler_config is None:
        handler = DbAuthorizationHandler(identity_provider_factory=idp_factory)
    elif handler_config == "external":
        handler = ExternalAuthorizationHandler(identity_provider_factory=idp_factory)
    else:
        raise Exception("Unknown authorization handler: {}".format(handler_config))

    handler.load(configuration.get("authorization_handler_config", {}))
    _global_authorizer = handler


def get_authorizer():
    return _global_authorizer


def lookup_account_type_from_identity(identity):
    if ApiRequestContextProxy.identity().username == identity:
        return ApiRequestContextProxy.identity().user_account_type
    else:
        return None
