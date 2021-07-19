"""
Base types for all anchore engine services
"""

import copy
import enum
import json
import os
import threading
import time
from pathlib import Path

import connexion
import yaml
from flask import g, jsonify

from anchore_engine import monitors
from anchore_engine.apis.authorization import get_authorizer, init_authz_handler
from anchore_engine.apis.exceptions import AnchoreApiError
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.common.helpers import make_response_error
from anchore_engine.configuration import localconfig
from anchore_engine.configuration.localconfig import (
    InvalidOauthConfigurationError,
)
from anchore_engine.db import db_services
from anchore_engine.db import initialize as initialize_db
from anchore_engine.db import session_scope
from anchore_engine.subsys import logger, metrics, servicestatus, taskstate
from anchore_engine.subsys.events import ServiceAuthzPluginHealthCheckFailed
from anchore_engine.subsys.identities import manager_factory


class LifeCycleStages(enum.IntEnum):
    """
    Ordered lifecycle stages by execution order
    """

    pre_config = 0
    post_config = 1
    pre_db = 2
    post_db = 3
    pre_credentials = 4
    post_credentials = 5
    pre_bootstrap = 6
    post_bootstrap = 7
    pre_register = 8
    post_register = 9


# Default handlers set at system level, will be modified by instantiation of BaseService at instance-level
_default_lifecycle_handlers = {
    LifeCycleStages.pre_config: [],
    LifeCycleStages.post_config: [],
    LifeCycleStages.pre_db: [],
    LifeCycleStages.post_db: [],
    LifeCycleStages.pre_credentials: [],
    LifeCycleStages.post_credentials: [],
    LifeCycleStages.pre_bootstrap: [],
    LifeCycleStages.post_bootstrap: [],
    LifeCycleStages.pre_register: [],
    LifeCycleStages.post_register: [],
}


def handle_api_exception(ex: AnchoreApiError):
    """
    Returns the proper json for marshalling an AnchoreApiError
    :param ex:
    :return:
    """
    return (
        jsonify(
            make_response_error(
                ex.message,
                in_httpcode=ex.__response_code__,
                details=ex.detail if ex.detail else {},
            )
        ),
        ex.__response_code__,
    )


class ServiceMeta(type):
    """
    Metaclass to create a registry for all subclasses of Gate for finding, building, and documenting the services

    """

    def __init__(cls, name, bases, dct):
        if not hasattr(cls, "registry"):
            cls.registry = {}
        else:
            if "__service_name__" in dct:
                svc_id = dct["__service_name__"].lower()
                cls.registry[svc_id] = cls

        super(ServiceMeta, cls).__init__(name, bases, dct)

    def get_service_by_name(cls, name):
        # Try direct name
        found = cls.registry.get(name.lower())
        if found:
            return found
        else:
            raise KeyError(name)

    def registered_service_types(cls):
        return list(cls.registry.keys())


class BaseService(object, metaclass=ServiceMeta):
    """
    Base type for all services to inherit from.

    An anchore engine service always has:
    healthcheck api - GET /health responds with 200 OK.
    monitor thread - to schedule async tasks and handle service status updates upstream
    versioned api - /vX/...

    Services have similar bootstrap and initialization path:
    self.configure() - load config
    self.db_connect() - setup db connections
    self.credential_init() - load system credentials
    self.bootstrap() - service-specific bootstrap that involves db and maybe other services
    self.register() - register the service in the db for discoverability

    These are all invoked in order from the bootstrap() function directly.

    Class variables:
    __is_unique_service__  = determines whether the system should allow more than one of this service instance to be registered.
    __service_name__ = The name used to identify this service class in both the service records and in config.
    __db_enabled__ = True|False determines if this service depends on the db and should connnect (default = True)
    __monitors__ = Dict of monitor configurations for this service
    __monitor_fn__ = Function to invoke as base thread monitor
    __service_api_version__ = str version name to use as prefix for api calls: e.g. /<__service_api_version__>/images
    __lifecycle_handlers__ = dict of mappings from LifeCycleStages to (function, arg) pairs to merge into the global defaults on instantiation
    """

    __is_unique_service__ = False
    __service_name__ = None
    __db_enabled__ = True
    __monitors__ = {}
    __monitor_fn__ = monitors.monitor
    __service_api_version__ = "v1"
    __lifecycle_handlers__ = {}
    __require_system_user__ = True
    __task_handlers_enabled__ = True

    def __init__(self, options=None):
        self.name = self.__service_name__
        self.options = options if options is not None else {}
        self.global_configuration = None
        self.requires_db = None
        self.require_system_user = self.__require_system_user__
        self.lifecycle_handlers = copy.deepcopy(_default_lifecycle_handlers)
        self.lifecycle_handlers.update(self.__lifecycle_handlers__)

        self.instance_id = None
        self.versions = None
        self.configuration = None
        self.fq_name = None
        self.monitor_fn = self.__monitor_fn__
        self.monitor_kwargs = {}
        self.monitor_threads = {}
        self.service_record = {}
        self.task_handlers_enabled = self.__task_handlers_enabled__

    @property
    def is_enabled(self):
        if self.configuration:
            return self.configuration.get("enabled", False)
        else:
            return False

    def _register_instance_handlers(self):
        """
        Called before the bootstrap process is initiated to allow overriding classes to modify the handlers

        :return:
        """
        return

    def _process_stage_handlers(self, stage):
        logger.info(
            "Processing init handlers for bootsrap stage: {}".format(stage.name)
        )
        handlers = self.lifecycle_handlers.get(stage, [])
        logger.debug("Executing {} stage {} handlers".format(len(handlers), stage.name))
        for handler_fn, handler_args in handlers:
            try:
                logger.debug(
                    "Invoking handler: {} with args {}".format(
                        handler_fn.__name__, handler_args
                    )
                )
                if handler_args is not None:
                    handler_fn(*handler_args)
                else:
                    handler_fn()
                logger.debug(
                    "Handler: {} completed successfully".format(
                        handler_fn.__name__, handler_args
                    )
                )
            except Exception as ex:
                logger.exception(
                    "Pre-Stage Handler {} for service pre_config raised exception".format(
                        handler_fn.__name__
                    )
                )
                raise ex

    def register_handler(self, stage, handler_fn, handler_args=None):
        """
        Register handlers for specific lifecycle stages

        :param stage: LifeCycleState enum obj to register for
        :param handler_fn: function to invoke
        :param handler_args: list of arguments to pass to the handler in order handler_fn(*handler_args)
        :return:
        """

        assert isinstance(stage, LifeCycleStages)
        if stage in self.lifecycle_handlers:
            self.lifecycle_handlers[stage].append((handler_fn, handler_args))
        else:
            raise KeyError(stage)

    def _get_service_configuration(self, global_config):
        """
        Extract service config from the global config.

        Override or supplement this function if a service needs configuration that isn't strictly in its 'service' entry.
        Should be a very rare occurance.

        :param global_config:
        :return: service configuration for this service
        """
        assert self.__service_name__ in global_config["services"]
        return global_config["services"][self.__service_name__]

    def configure(self):
        self._process_stage_handlers(LifeCycleStages.pre_config)
        self._configure()
        self._process_stage_handlers(LifeCycleStages.post_config)

    def _init_versions(self):
        """
        Initialize the service versions
        :return:
        """
        try:
            self.versions = localconfig.get_versions()
        except Exception as err:
            logger.error("cannot detect versions of service: exception - " + str(err))
            raise err

    def _configure(self):
        """
        Load service configuration

        :return:
        """
        logger.info("Loading and initializing global configuration")
        self._init_versions()

        self.configuration = self._get_service_configuration(self.global_configuration)
        self.instance_id = localconfig.get_host_id()
        self.fq_name = (self.name, self.instance_id)

        self.task_handlers_enabled = self.configuration.get(
            "task_handlers_enabled", True
        )
        env_setting = (
            not os.environ.get("ANCHORE_ENGINE_DISABLE_MONITORS", "false").lower()
            == "true"
        )
        self.task_handlers_enabled = self.task_handlers_enabled and env_setting

        if not self.task_handlers_enabled:
            if env_setting:
                logger.warn(
                    "Task handlers disabled by setting ANCHORE_ENGINE_DISABLE_MONITORS in environment"
                )
            else:
                logger.warn("Task handlers disabled by configuration file value")

        try:
            kick_timer = int(self.configuration["cycle_timer_seconds"])
        except:
            kick_timer = 1

        try:
            cycle_timers = {}
            cycle_timers.update(self.configuration["cycle_timers"])
        except:
            cycle_timers = {}

        self.monitor_kwargs["kick_timer"] = kick_timer
        self.monitor_kwargs["cycle_timers"] = cycle_timers
        self.monitor_kwargs["monitors"] = copy.deepcopy(self.__monitors__)
        self.monitor_kwargs["monitor_threads"] = self.monitor_threads
        self.monitor_kwargs["servicename"] = self.name
        logger.info("Configuration complete")

    def db_connect(self):
        self._process_stage_handlers(LifeCycleStages.pre_db)
        self._db_connect()
        self._process_stage_handlers(LifeCycleStages.post_db)

    def _db_connect(self):
        """
        Initialize the db connection and prepare the db
        :return:
        """
        logger.info("Configuring db connection")
        if not self.db_connect:
            logger.info(
                "DB Connection disabled in configuration for service {}. Skipping db init".format(
                    self.__service_name__
                )
            )
            return True

        logger.info("Initializing database")
        # connect to DB
        try:
            initialize_db(localconfig=self.global_configuration, versions=self.versions)
        except Exception as err:
            logger.error("cannot connect to configured DB: exception - " + str(err))
            raise err

        logger.info("DB connection initialization complete")

    def credential_init(self):
        self._process_stage_handlers(LifeCycleStages.pre_credentials)
        self._credential_init()
        self._process_stage_handlers(LifeCycleStages.post_credentials)

    def _credential_init(self):
        logger.info("Bootstrapping credentials")

        # credential bootstrap
        self.global_configuration["system_user_auth"] = (None, None)

        if self.require_system_user:
            gotauth = False
            max_retries = 60
            self.global_configuration["system_user_auth"] = (None, None)
            for count in range(1, max_retries):
                try:
                    with session_scope() as dbsession:
                        mgr = manager_factory.for_session(dbsession)
                        logger.info("Checking system creds")
                        c = mgr.get_system_credentials()
                    if c is not None:
                        logger.info("Found valid system creds")
                        gotauth = True
                        break
                    else:
                        logger.info("Did not find valid system creds")
                        logger.error(
                            "cannot get system user auth credentials yet, retrying ("
                            + str(count)
                            + " / "
                            + str(max_retries)
                            + ")"
                        )
                        time.sleep(5)
                except InvalidOauthConfigurationError:
                    raise
                except Exception as err:
                    logger.exception(
                        "cannot get system-user auth credentials - service may not have system level access"
                    )
                    self.global_configuration["system_user_auth"] = (None, None)
                    gotauth = False

            if not gotauth:
                raise Exception("service requires system user auth to start")

        logger.info("Credential initialization complete")

    def bootstrap(self):
        self._process_stage_handlers(LifeCycleStages.pre_bootstrap)
        self._bootstrap()
        self._process_stage_handlers(LifeCycleStages.post_bootstrap)

    def _bootstrap(self):
        """
        Create and init the service
        :return:
        """
        # Do monitor-thread bootstraps here
        logger.info("Bootstrapping service")
        logger.info("Service bootstrap complete")
        return True

    def register(self):
        self._process_stage_handlers(LifeCycleStages.pre_register)
        self._register()
        self._process_stage_handlers(LifeCycleStages.post_register)

    def _register(self):
        if not self.is_enabled:
            logger.error(
                "Service not enabled in config, not registering service: " + self.name
            )
            raise Exception("No service enabled, cannot continue bootstrap")

        logger.info("Registering service: {}".format(self.name))

        service_template = {
            "type": "anchore",
            "base_url": "N/A",
            "status_base_url": "N/A",
            "version": "v1",
            "short_description": "",
        }

        hstring = "http"
        if "external_tls" in self.configuration:
            if self.configuration.get("external_tls", False):
                hstring = "https"
        elif "ssl_enable" in self.configuration:
            if self.configuration.get("ssl_enable", False):
                hstring = "https"

        endpoint_hostname = endpoint_port = endpoint_hostport = None
        if self.configuration.get("external_hostname", False):
            endpoint_hostname = self.configuration.get("external_hostname")
        elif self.configuration.get("endpoint_hostname", False):
            endpoint_hostname = self.configuration.get("endpoint_hostname")

        if self.configuration.get("external_port", False):
            endpoint_port = int(self.configuration.get("external_port"))
        elif self.configuration.get("port", False):
            endpoint_port = int(self.configuration.get("port"))

        if endpoint_hostname:
            endpoint_hostport = endpoint_hostname
            if endpoint_port:
                endpoint_hostport = endpoint_hostport + ":" + str(endpoint_port)

        if endpoint_hostport:
            service_template["base_url"] = "{}://{}".format(hstring, endpoint_hostport)
        else:
            raise Exception(
                "could not construct service base_url - please check service configuration for hostname/port settings"
            )

        try:
            service_template["status"] = False
            service_template["status_message"] = taskstate.base_state("service_status")

            with session_scope() as dbsession:
                service_records = db_services.get_byname(
                    self.__service_name__, session=dbsession
                )

                # fail if trying to add a service that must be unique in the system, but one already is registered in DB
                if self.__is_unique_service__:
                    if len(service_records) > 1:
                        raise Exception(
                            "more than one entry for service type ("
                            + str(self.__service_name__)
                            + ") exists in DB, but service must be unique - manual DB intervention required"
                        )

                    for service_record in service_records:
                        if service_record and (
                            service_record["hostid"] != self.instance_id
                        ):
                            raise Exception(
                                "service type ("
                                + str(self.__service_name__)
                                + ") already exists in system with different host_id - detail: my_host_id="
                                + str(self.instance_id)
                                + " db_host_id="
                                + str(service_record["hostid"])
                            )

                # if all checks out, then add/update the registration
                ret = db_services.add(
                    self.instance_id,
                    self.__service_name__,
                    service_template,
                    session=dbsession,
                )

                try:
                    my_service_record = {
                        "hostid": self.instance_id,
                        "servicename": self.__service_name__,
                    }
                    my_service_record.update(service_template)
                    servicestatus.set_my_service_record(my_service_record)
                    self.service_record = my_service_record
                except Exception as err:
                    logger.warn(
                        "could not set local service information - exception: {}".format(
                            str(err)
                        )
                    )

        except Exception as err:
            raise err

        service_record = servicestatus.get_my_service_record()
        servicestatus.set_status(
            service_record,
            up=True,
            available=True,
            update_db=True,
            versions=self.versions,
        )
        logger.info("Service registration complete")
        return True

    def initialize(
        self, global_configuration, db_connect=True, require_system_user_auth=None
    ):
        """
        Service initialization that requires the service config loaded and available but before registration of the service
        or db connection and access to service discovery.


        :param name: str name of service instance
        :param db_connect: override the __db_enabled__ class variable just for this instance. If false, no db init or connect is performed on bootstrap
        :param global_configuration: dict of configuration data to use
        :return: True on success
        """

        self.global_configuration = global_configuration
        self.requires_db = db_connect

        if require_system_user_auth is not None:
            self.require_system_user = require_system_user_auth

        logger.debug("Invoking instance-specific handler registration")
        self._register_instance_handlers()

        self.configure()
        self.db_connect()
        self.credential_init()
        self.bootstrap()
        self.register()

        return True

    def get_monitor_thread(self, monitor_thread_wrapper=None):
        """
        Start the service and return a thread to execute the monitor. Caller must actually start the monitor thread for this service.

        :param monitor_thread_wrapper: function that takes the target function and **kwargs as arguments and returns an object expected by the caller
        :return:
        """

        if self.task_handlers_enabled:
            if monitor_thread_wrapper:
                t = monitor_thread_wrapper(self.monitor_fn, **self.monitor_kwargs)
            else:
                t = threading.Thread(target=self.monitor_fn, kwargs=self.monitor_kwargs)

            return t
        else:
            return None


class ApiService(BaseService):
    """
    A service that provides an api
    """

    __spec_dir__ = "swagger"
    __spec_file__ = "swagger.yaml"
    __service_api_version__ = "v1"

    def __init__(self, options=None):
        super().__init__(options=options)
        self._api_application = None
        self.yosai = None

    def _register_instance_handlers(self):
        super()._register_instance_handlers()
        logger.info("Registering api handlers")
        self.register_handler(LifeCycleStages.pre_bootstrap, self.initialize_api, None)

    def _init_wsgi_app(self, service_name, api_spec_dir=None, api_spec_file=None):
        """
        Return an initialized service with common api resource and auth config
        :return:
        """

        try:

            enable_swagger_ui = False
            if self.configuration.get("enable_swagger_ui", None) is not None:
                enable_swagger_ui = self.configuration.get("enable_swagger_ui")
            elif self.global_configuration.get("enable_swagger_ui", None) is not None:
                enable_swagger_ui = self.global_configuration.get("enable_swagger_ui")

            flask_app_options = {"swagger_ui": enable_swagger_ui}
            self._application = connexion.FlaskApp(
                __name__, specification_dir=api_spec_dir, options=flask_app_options
            )
            flask_app = self._application.app
            flask_app.url_map.strict_slashes = False

            # Ensure jsonify() calls add whitespace for nice error responses
            flask_app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

            # Suppress some verbose logs in dependencies
            import logging as py_logging

            py_logging.basicConfig(level=py_logging.ERROR)

            # Initialize the authentication system
            self.init_auth()

            flask_app.before_request(self._inject_service)
            flask_app.register_error_handler(AnchoreApiError, handle_api_exception)

            metrics.init_flask_metrics(flask_app, servicename=service_name)
            self._application.add_api(
                Path(api_spec_file),
                validate_responses=self.options.get("validate-responses"),
            )

            return self._application
        except Exception as err:
            logger.exception("Error initializing WSGI application")
            raise

    def init_auth(self):
        """
        Initializes the authentication subsystem as needed
        :return:
        """
        # Initialize the wrapper
        init_authz_handler(configuration=self.configuration)

    def _inject_service(self):
        """
        Adds a reference to the service object into the request's app context
        :return:
        """
        g.service = self

    def initialize_api(self):
        """
        Initialize the api and return the wsgi application object
        :return:
        """

        logger.info(
            "Initializing API from: {}/{}".format(self.__spec_dir__, self.__spec_file__)
        )
        if (
            self.configuration["listen"]
            and self.configuration["port"]
            and self.configuration["endpoint_hostname"]
        ):
            if not self._api_application:
                self._api_application = self._init_wsgi_app(
                    self.__service_name__, self.__spec_dir__, self.__spec_file__
                )

    def get_api_application(self):
        if self._api_application is None:
            raise Exception(
                "API not initialized yet. Must initialize the service or call initialize_api() before the application is available"
            )

        return self._api_application.app

    @staticmethod
    def build_authz_heartbeat(service_name):
        """
        Returns the handler function itself (uses closure to pass some values in
        :return:
        """

        def authz_heartbeat(*args, **kwargs):
            cycle_timer = kwargs["mythread"]["cycle_timer"]
            logger.info("Checking authz availability")
            try:
                host_id = localconfig.get_host_id()
                authz_handlr = get_authorizer()
                handler = authz_handlr.__class__.__name__
                ex = None
                try:
                    result = authz_handlr.healthcheck()
                except Exception as e:
                    ex = e
                    result = False

                if not result:
                    fail_event = ServiceAuthzPluginHealthCheckFailed(
                        user_id=localconfig.ADMIN_ACCOUNT_NAME,
                        name=service_name,
                        host=host_id,
                        plugin=handler,
                        details=str(ex),
                    )
                    logger.info(
                        "Sending healthcheck failure event: {}".format(
                            fail_event.__event_type__
                        )
                    )

                    try:
                        client = internal_client_for(
                            CatalogClient, localconfig.ADMIN_ACCOUNT_NAME
                        )
                        client.add_event(fail_event)
                    except Exception as ex:
                        logger.exception(
                            "Failure to send authz healthcheck failure event: {}".format(
                                fail_event.to_json()
                            )
                        )

            except Exception as e:
                logger.exception(
                    "Caught unexpected exception from the authz heartbeat handler"
                )

            time.sleep(cycle_timer)
            return True

        return authz_heartbeat


class UserFacingApiService(ApiService):
    def __init__(self, options=None):
        super().__init__(options)
        self._authz_actions = {}
        self.api_spec = None

    def _register_instance_handlers(self):
        super()._register_instance_handlers()
        self.register_handler(
            LifeCycleStages.pre_bootstrap, self._process_api_spec, None
        )

    @staticmethod
    def parse_swagger(path):
        with open(path) as f:
            if path.endswith("yaml") or path.endswith("yml"):
                return yaml.safe_load(f)
            else:
                return json.load(f)

    @staticmethod
    def build_action_map(swagger_content):
        """
        Given a dict from the swagger spec (must be fully materialized, no external refs), determine the mapping
        of a operation to an action using x-anchore-action labels in the swagger.

        This relies on using connexion such that the x-swagger-router-controller + operationId define the key as is implemented
        in connexion. The resulting dict maps a fully-qualified function to an action

        :param swagger_content: dict
        :return: dict function_name -> action (e.g. anchore_engine.services.apiext.images.list_images -> listImages)
        """

        action_map = {}
        for path in swagger_content.get("paths").values():
            for verb in path.values():
                action = verb.get("x-anchore-authz-action")
                controller = verb.get("x-swagger-router-controller")
                operationId = verb.get("operationId")
                action_map[controller + "." + operationId] = action

        return action_map

    def _process_api_spec(self):
        try:
            self.api_spec = UserFacingApiService.parse_swagger(
                os.path.join(self.__spec_dir__, self.__spec_file__)
            )
            actions = UserFacingApiService.build_action_map(self.api_spec)
            missing = [x for x in filter(lambda x: x[1] is None, actions.items())]
            if missing:
                raise Exception(
                    "API Spec validation error: All operations must have a x-anchore-authz-action label. Missing for: {}".format(
                        missing
                    )
                )
            else:
                self._authz_actions = actions
        except Exception as ex:
            logger.exception(
                "Error loading swagger spec for authz action parsing. Cannot proceed"
            )
            raise ex

    def action_for_operation(self, fq_operation_id):
        """
        Raises KeyError if id not found

        :param fq_operation_id:
        :return:
        """
        return self._authz_actions[fq_operation_id]
