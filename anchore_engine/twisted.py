"""
Twisted framework specific code for base plugin functionality. Used by each plugin definition.

"""

import datetime
import faulthandler
import json
import os
import sys

from twisted.application.internet import StreamServerEndpointService, TimerService
from twisted.internet import reactor, ssl
from twisted.internet.endpoints import SSL4ServerEndpoint, TCP4ServerEndpoint
from twisted.internet.task import LoopingCall
from twisted.python import log, usage
from twisted.web import rewrite, server, wsgi
from twisted.web.resource import Resource

from anchore_engine.apis.ssl import _load_ssl_cert, _load_ssl_key
from anchore_engine.configuration import localconfig
from anchore_engine.service import ApiService
from anchore_engine.subsys import logger

# For the debug CLI, require a code modification to enable it. This allows on-host edits of the script and restart, but no accidental config from env vars or config.
enable_dangerous_debug_cli = False

# Thread dumper is safer since read-only and only on local-host, so allow it to configure from env var
enable_thread_dumper = (
    os.getenv("ANCHORE_ENABLE_DANGEROUS_THREAD_DUMP_API", "false").lower() == "true"
)

if enable_dangerous_debug_cli or enable_thread_dumper:
    from twisted.application import internet, service  # pylint: disable=C0412
    from twisted.conch.insults import insults  # pylint: disable=C0412
    from twisted.conch.manhole import ColoredManhole  # pylint: disable=C0412
    from twisted.conch.telnet import TelnetBootstrapProtocol  # pylint: disable=C0412
    from twisted.conch.telnet import TelnetTransport  # pylint: disable=C0412
    from twisted.internet import protocol  # pylint: disable=C0412


class CommonOptions(usage.Options):
    """
    Default Anchore CLI options for the twistd plugins
    """

    optParameters = [
        ["config", "c", None, "Configuration directory location."],
        [
            "validate-responses",
            "r",
            False,
            "Enable response validation.",
            lambda x: x in ["True", "true", "t", True],
        ],
    ]


class ThreadDumperResource(Resource):
    isLeaf = True

    def __init__(self):
        super().__init__()
        logger.info("Initializing thread dumper resource")

    def render_GET(self, request):
        logger.info("Handling thread dump request")

        try:
            with open(
                "/var/log/anchore/pid_{}_thread_dump-{}".format(
                    os.getpid(), datetime.datetime.now().isoformat()
                ),
                "w",
            ) as dest:
                faulthandler.dump_traceback(dest, all_threads=True)
        except:
            logger.exception("Error dumping thread frames")
            return b"Failed"

        return b"Sucess"


def _load_config(config_option, validate_params=None):
    try:
        # config and init
        configfile = configdir = None
        if config_option:
            configdir = config_option
            configfile = os.path.join(config_option, "config.yaml")

        localconfig.load_config(
            configdir=configdir, configfile=configfile, validate_params=validate_params
        )
        my_config = localconfig.get_config()
        my_config["myservices"] = []
        logger.spew("localconfig=" + json.dumps(my_config, indent=4, sort_keys=True))
        return my_config
    except Exception as err:
        logger.error("cannot load configuration: exception - " + str(err))
        raise err


def _validate_options(options):
    if "config" not in options:
        raise Exception('Invalid startup options. "config" must be specified')
    return options


class WsgiApiServiceMaker(object):
    """
    A service maker that builds twistd api handlers as well. Includes the /health resource by default

    """

    service_cls = None
    tapname = None  # e.g. "anchore-api"
    description = None  # e.g. "Anchore Service"
    options = CommonOptions

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.global_configuration = None
        self.service_config = None
        self.anchore_service = None
        self.root_resource = None
        self.twistd_service = None
        self.resource_nodes = {}

    def _init_logging(self):
        if self.global_configuration is None:
            log.err(
                "No configuration found to initialize logging for. Expecting other errors, so setting log level to DEBUG"
            )
            log_level = "DEBUG"
            log_to_db = False
        else:
            try:
                service_config = self.global_configuration["services"][
                    self.service_cls.__service_name__
                ]
                log_level = service_config.get(
                    "log_level", self.global_configuration.get("log_level", "INFO")
                )
                log_to_db = self.global_configuration.get("log_to_db", False)
            except Exception as err:
                log.err(
                    "error checking for enabled services, check config file - exception: "
                    + str(err)
                )
                raise Exception(
                    "error checking for enabled services, check config file - exception: "
                    + str(err)
                )

        logger.set_log_level(log_level, log_to_db=log_to_db)

    def _check_enabled(self):
        if (
            not self.global_configuration.get("services", {})
            .get(self.service_cls.__service_name__, {})
            .get("enabled", False)
        ):
            log.err(
                "Service {} not enabled in configuration file: shutting down".format(
                    self.service_cls.__service_name__
                )
            )
            sys.exit(0)

    def _init_config(self, options):
        _validate_options(options)
        self.global_configuration = _load_config(options["config"])
        self.service_config = self.global_configuration.get("services", {}).get(
            self.service_cls.__service_name__, {}
        )

    def _get_non_api_monitor(self, service):
        return service.get_monitor_thread(
            monitor_thread_wrapper=lambda target, kwargs: TimerService(
                1, target, **kwargs
            )
        )

    def _get_api_monitor(self, service):
        return service.get_monitor_thread(monitor_thread_wrapper=LoopingCall)

    def makeDebugCLIService(self, args):
        """
        This is dangerous, and should only ever be enabled by explicit user config and only for non-production use

        :param args:
        :return:
        """

        f = protocol.ServerFactory()
        f.protocol = lambda: TelnetTransport(
            TelnetBootstrapProtocol,
            insults.ServerProtocol,
            args["protocolFactory"],
            *args.get("protocolArgs", ()),
            **args.get("protocolKwArgs", {})
        )
        return internet.TCPServer(args["telnet"], f)

    def makeService(self, options):

        try:
            logger.info("Initializing configuration")
            try:
                self._init_config(options)
            except Exception as e:
                logger.error(
                    "Aborting service startup due to configuration error: {}".format(e)
                )
                raise e

            logger.info("Initializing logging")
            self._init_logging()

            self._check_enabled()

            # logger.enable_bootstrap_logging(self.tapname)

            assert issubclass(self.service_cls, ApiService)
            self.anchore_service = self.service_cls(options=options)
            self.anchore_service.initialize(self.global_configuration)

            # application object
            application = service.Application(
                "Service-" + "-".join(self.anchore_service.name)
            )
            self.twistd_service = service.MultiService()
            self.twistd_service.setServiceParent(application)

            if self.anchore_service.task_handlers_enabled:
                logger.info("Starting monitor thread")
                lc = self._get_api_monitor(self.anchore_service)
                lc.start(1)
            else:
                logger.warn(
                    "Skipped start of monitor threads due to task_handlers_enabled=false in config, or found ANCHORE_ENGINE_DISABLE_MONITORS in env"
                )

            thread_stats_interval = int(
                self.service_config.get("debug_thread_stats_dump_interval", 0)
            )
            if thread_stats_interval > 0:
                logger.info("Based on service config, starting the thread stats dumper")
                monitor = LoopingCall(dump_stats)
                monitor.start(thread_stats_interval)

            logger.info("Building api handlers")
            s = self._build_api_service()
            s.setServiceParent(self.twistd_service)

            if enable_dangerous_debug_cli:
                logger.warn(
                    "Loading *dangerous* debug/telnet service as specified by debug config"
                )
                self.makeDebugCLIService(
                    {
                        "protocolFactory": ColoredManhole,
                        "protocolArgs": (None,),
                        "telnet": 6023,
                    }
                ).setServiceParent(self.twistd_service)

            return self.twistd_service

        except Exception as err:
            logger.exception(
                "cannot create/init/register service: "
                + self.service_cls.__service_name__
                + " - exception: "
                + str(err)
            )
            raise Exception("cannot start service (see above for information)")
        finally:
            pass
            # logger.disable_bootstrap_logging()

    def _add_resource(self, name, resource):
        """
        Add a resource to this resource as a child
        :param resource: Resource subclass object
        :param name: path name for the resource (as bytes object)
        :return:
        """

        self.resource_nodes[name] = resource

    def _build_api_service(self):
        """
        Once called, the resource is initialized. Any calls to self._add_resource() should be done before calling this fn.
        :return:
        """

        thread_count = int(
            self.service_config.get(
                "max_request_threads", localconfig.DEFAULT_SERVICE_THREAD_COUNT
            )
        )

        wsgi_app = self.anchore_service.get_api_application()
        wsgi_site = wsgi.WSGIResource(
            reactor, reactor.getThreadPool(), application=wsgi_app
        )
        reactor.getThreadPool().adjustPoolsize(maxthreads=thread_count)
        logger.debug(
            "Thread pool size stats. Min={}, Max={}".format(
                reactor.getThreadPool().min, reactor.getThreadPool().max
            )
        )

        self._add_resource(
            self.anchore_service.__service_api_version__.encode("utf-8"), wsgi_site
        )

        if enable_thread_dumper:
            logger.warn(
                "Adding thread dump route for debugging since debug flag is set. This is dangerous and should not be done in normal production"
            )
            self._add_resource(b"threads", ThreadDumperResource())

        self.root_resource = Resource()

        # Add nodes
        for name, resource in self.resource_nodes.items():
            self.root_resource.putChild(name, resource)

        # this will rewrite any calls that do not have an explicit version to the base path before being processed by flask
        self._api_version_bytes = self.anchore_service.__service_api_version__.encode(
            "utf-8"
        )  # This is optimization

        # Handle the auth vs non-auth child resources to not consume a path element
        root = rewrite.RewriterResource(
            self.root_resource, self._default_version_rewrite
        )

        # Build the main site server
        server_request_timeout_seconds = self.service_config.get(
            "server_request_timeout_seconds",
            self.global_configuration.get("server_request_timeout_seconds", 180),
        )
        site = server.Site(root, timeout=server_request_timeout_seconds)
        listen = self.anchore_service.configuration["listen"]

        # Disable the twisted access logging by overriding the log function as it uses a raw 'write' and cannot otherwise be disabled, iff enable_access_logging is set to False in either the service or global config
        try:
            eal = True
            if "enable_access_logging" in self.anchore_service.configuration:
                eal = self.anchore_service.configuration.get(
                    "enable_access_logging", True
                )
            elif "enable_access_logging" in self.configuration:
                eal = self.configuration.get("enable_access_logging", True)

            if not eal:

                def _null_logger(request):
                    pass

                site.log = _null_logger

        except:
            pass

        if (
            str(self.anchore_service.configuration.get("ssl_enable", "")).lower()
            == "true"
        ):
            try:
                ssl_data = {
                    "ssl_cert": _load_ssl_cert(
                        self.anchore_service.configuration["ssl_cert"]
                    )
                    if "ssl_cert" in self.anchore_service.configuration
                    else None,
                    "ssl_chain": _load_ssl_cert(
                        self.anchore_service.configuration["ssl_chain"]
                    )
                    if "ssl_chain" in self.anchore_service.configuration
                    else None,
                    "ssl_key": _load_ssl_key(
                        self.anchore_service.configuration["ssl_key"]
                    )
                    if "ssl_key" in self.anchore_service.configuration
                    else None,
                }

                if ssl_data["ssl_chain"]:
                    sfact = ssl.CertificateOptions(
                        privateKey=ssl_data["ssl_key"],
                        certificate=ssl_data["ssl_cert"],
                        extraCertChain=[ssl_data["ssl_chain"]],
                    )
                else:
                    sfact = ssl.CertificateOptions(
                        privateKey=ssl_data["ssl_key"], certificate=ssl_data["ssl_cert"]
                    )

                endpoint = SSL4ServerEndpoint(
                    reactor=reactor,
                    port=int(self.anchore_service.configuration["port"]),
                    sslContextFactory=sfact,
                    interface=listen,
                )
            except Exception as err:
                raise err
        else:
            endpoint = TCP4ServerEndpoint(
                reactor=reactor,
                port=int(self.anchore_service.configuration["port"]),
                interface=listen,
            )

        ret_svc = StreamServerEndpointService(endpoint=endpoint, factory=site)
        ret_svc.setName(self.anchore_service.name)

        return ret_svc

    def _default_version_rewrite(self, request):
        try:
            if request.postpath:
                # if request.postpath[0] != b'health' and request.postpath[0] != self._api_version_bytes:
                if (
                    request.postpath[0] not in self.resource_nodes.keys()
                    and request.postpath[0] != self._api_version_bytes
                ):
                    request.postpath.insert(0, self._api_version_bytes)
                    request.path = b"/" + self._api_version_bytes + request.path
        except Exception as err:
            logger.error("rewrite exception: " + str(err))
            raise err


def dump_stats():
    """
    Dump some basic stats about the reactor pool and threads at info level
    :return:
    """

    logger.info(
        "Reactor queue stats: {}".format(
            reactor.getThreadPool()._team.statistics().__dict__
        )
    )
