"""
Twisted framework specific code for base plugin functionality. Used by each plugin definition.

"""

import copy
import json
import os
import sys
from twisted import web
from twisted.application import service
from twisted.application.internet import TimerService, StreamServerEndpointService
from twisted.internet.endpoints import TCP4ServerEndpoint, SSL4ServerEndpoint

from twisted.internet import ssl, reactor
from twisted.internet.task import LoopingCall
from twisted.python import log
from twisted.python import usage
from twisted.web.resource import Resource
from twisted.web import wsgi, rewrite
from twisted.web import server

from anchore_engine.apis.ssl import _load_ssl_key, _load_ssl_cert
from anchore_engine.subsys import logger
from anchore_engine.configuration import localconfig
from anchore_engine.service import ApiService
from anchore_engine import utils


class CommonOptions(usage.Options):
    """
    Default Anchroe CLI options for the twistd plugins
    """

    optParameters = [
        ["config", "c", None, "Configuration directory location."],
        ["validate-responses", "r", False, "Enable response validation.", lambda x: x in ['True', 'true', 't', True]]
    ]


# simple twisted resource for health check route
class EmptyResource(Resource):
    """
    A simple resource to return empty if rendered
    """
    isLeaf = True

    def render_GET(self, request):
        return b''


# simple twisted resource for version check route
class VersionResource(Resource):
    """
    A simple resource to return version information if rendered
    """
    isLeaf = True

    def __init__(self, versions):
        super().__init__()
        self.versions = versions

    def render_GET(self, request):
        request.responseHeaders.addRawHeader(b"Content-Type", b"application/json")

        ret = {
            'service': {
                'version': self.versions.get('service_version', None),
            },
            'api': {
            },
            'db': {
                'schema_version': self.versions.get('db_version', None),
            }
        }

        try:
            response = utils.ensure_bytes(json.dumps(ret))
        except:
            response = utils.ensure_bytes(json.dumps({}))

        return response


def _load_config(config_option, validate_params=None):
    try:
        # config and init
        configfile = configdir = None
        if config_option:
            configdir = config_option
            configfile = os.path.join(config_option, 'config.yaml')

        localconfig.load_config(configdir=configdir, configfile=configfile, validate_params=validate_params)
        my_config = localconfig.get_config()
        my_config['myservices'] = []
        logger.spew("localconfig=" + json.dumps(my_config, indent=4, sort_keys=True))
        return my_config
    except Exception as err:
        logger.error("cannot load configuration: exception - " + str(err))
        raise err


def _validate_options(options):
    if 'config' not in options:
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

    # The base child paths served by this service (e.g. /health, /v1/...). A list of web.resource.Resource() objects
    _default_resource_nodes = {
        b'health': EmptyResource(),
        b'version': VersionResource({})
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.configuration = None
        self.anchore_service = None
        self.root_resource = None
        self.twistd_service = None
        self.configuration = None
        self.resource_nodes = copy.deepcopy(self._default_resource_nodes)

    def _init_logging(self):
        if self.configuration is None:
            log.err('No configuration found to initialize logging for. Expecting other errors, so setting log level to DEBUG')
            log_level = 'DEBUG'
            log_to_db = False
        else:
            try:
                service_config = self.configuration['services'][self.service_cls.__service_name__]
                log_level = service_config.get('log_level', self.configuration.get('log_level', 'INFO'))
                log_to_db = self.configuration.get('log_to_db', False)
            except Exception as err:
                log.err("error checking for enabled services, check config file - exception: " + str(err))
                raise Exception("error checking for enabled services, check config file - exception: " + str(err))

        logger.set_log_level(log_level, log_to_db=log_to_db)

    def _check_enabled(self):
        if not self.configuration.get('services', {}).get(self.service_cls.__service_name__, {}).get('enabled', False):
            log.err("Service {} not enabled in configuration file: shutting down".format(self.service_cls.__service_name__))
            sys.exit(0)

    def _init_config(self, options):
        _validate_options(options)
        self.configuration = _load_config(options['config'])

    def _get_non_api_monitor(self, service):
        return service.get_monitor_thread(monitor_thread_wrapper=lambda target, kwargs: TimerService(1, target, **kwargs))

    def _get_api_monitor(self, service):
        return service.get_monitor_thread(monitor_thread_wrapper=LoopingCall)

    def makeService(self, options):

        try:
            logger.info('Initializing configuration')
            self._init_config(options)

            logger.info('Initializing logging')
            self._init_logging()

            self._check_enabled()

            #logger.enable_bootstrap_logging(self.tapname)

            assert (issubclass(self.service_cls, ApiService))
            self.anchore_service = self.service_cls(options=options)
            self.anchore_service.initialize(self.configuration)
            self.resource_nodes[b'version'].versions = self.anchore_service.versions

            # application object
            application = service.Application("Service-" + '-'.join(self.anchore_service.name))
            self.twistd_service = service.MultiService()
            self.twistd_service.setServiceParent(application)

            if not os.environ.get('ANCHORE_ENGINE_DISABLE_MONITORS'):
                logger.info('Starting monitor thread')
                lc = self._get_api_monitor(self.anchore_service)
                lc.start(1)
            else:
                logger.warn('Skipped start of monitor threads due to ANCHORE_ENGINE_DISABLE_MONITORS set in environment')

            logger.info('Building api handlers')
            s = self._build_api_service()
            s.setServiceParent(self.twistd_service)

            return self.twistd_service

        except Exception as err:
            logger.exception("cannot create/init/register service: " + self.service_cls.__service_name__ + " - exception: " + str(err))
            raise Exception("cannot start service (see above for information)")
        finally:
            pass
            #logger.disable_bootstrap_logging()

    def _add_resource(self, name, resource):
        """
        Add a resource to this resource as a child
        :param resource: Resource subclass object
        :param name: path name for the resource (as bytes object)
        :return:
        """

        self.resource_nodes[name] = resource


    # Old module-level createService()
    def _build_api_service(self):
        """
        Once called, the resource is initialized. Any calls to self._add_resource() should be done before calling this fn.
        :return:
        """

        wsgi_app = self.anchore_service.get_api_application()
        wsgi_site = wsgi.WSGIResource(reactor, reactor.getThreadPool(), application=wsgi_app)

        self._add_resource(self.anchore_service.__service_api_version__.encode('utf-8'), wsgi_site)
        self.root_resource = web.resource.Resource()

        # Add nodes
        for name, resource in self.resource_nodes.items():
            self.root_resource.putChild(name, resource)

        # this will rewrite any calls that do not have an explicit version to the base path before being processed by flask
        self._api_version_bytes = self.anchore_service.__service_api_version__.encode('utf-8') # This is optimization

        # Handle the auth vs non-auth child resources to not consume a path element
        root = rewrite.RewriterResource(self.root_resource, self._default_version_rewrite)

        # Build the main site server
        site = server.Site(root)
        listen = self.anchore_service.configuration['listen']


        if str(self.anchore_service.configuration.get('ssl_enable', '')).lower() == 'true':
            try:
                ssl_data = {
                    'ssl_cert': _load_ssl_cert(self.anchore_service.configuration['ssl_cert']) if 'ssl_cert' in self.anchore_service.configuration else None,
                    'ssl_chain': _load_ssl_cert(self.anchore_service.configuration['ssl_chain']) if 'ssl_chain' in self.anchore_service.configuration else None,
                    'ssl_key': _load_ssl_key(self.anchore_service.configuration['ssl_key']) if 'ssl_key' in self.anchore_service.configuration else None
                }

                if ssl_data['ssl_chain']:
                    sfact = ssl.CertificateOptions(privateKey=ssl_data['ssl_key'], certificate=ssl_data['ssl_cert'],
                                                   extraCertChain=[ssl_data['ssl_chain']])
                else:
                    sfact = ssl.CertificateOptions(privateKey=ssl_data['ssl_key'], certificate=ssl_data['ssl_cert'])

                endpoint = SSL4ServerEndpoint(reactor=reactor, port=int(self.anchore_service.configuration['port']), sslContextFactory=sfact, interface=listen)
            except Exception as err:
                raise err
        else:
            endpoint = TCP4ServerEndpoint(reactor=reactor, port=int(self.anchore_service.configuration['port']), interface=listen)

        ret_svc = StreamServerEndpointService(endpoint=endpoint, factory=site)
        ret_svc.setName(self.anchore_service.name)
        
        return ret_svc

    def _default_version_rewrite(self, request):
        try:
            if request.postpath:
                #if request.postpath[0] != b'health' and request.postpath[0] != self._api_version_bytes:
                if request.postpath[0] not in [b'health', b'version'] and request.postpath[0] != self._api_version_bytes:
                    request.postpath.insert(0, self._api_version_bytes)
                    request.path = b'/' + self._api_version_bytes + request.path
        except Exception as err:
            logger.error("rewrite exception: " + str(err))
            raise err
