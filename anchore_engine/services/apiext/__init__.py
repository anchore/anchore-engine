import re
import json
import traceback

import connexion
from connexion import request
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common
from anchore_engine.services.common import apiext_status
from anchore_engine.subsys import logger

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    application.app.url_map.strict_slashes = False
    application.add_api('swagger.yaml')
    flask_app = application.app
except Exception as err:
    traceback.print_exc()
    raise err

if False:
    @flask_app.before_request
    def preflight():
        global apiext_status

        try:
            httpcode = 200
            clean_endpoint = None
            if request.endpoint:
                clean_endpoint = re.sub("^\/v.*\.", "", request.endpoint)

            logger.debug("pre-flight endpoint: " + str(clean_endpoint))

            nonop_endpoints = ['anchore_engine_services_apiext_api_controllers_system_get_service_detail', 'anchore_engine_services_apiext_api_controllers_system_ping']
            if not clean_endpoint or clean_endpoint in nonop_endpoints:
                logger.debug("skipping service status checks due to non-op endpoint: " + str(request.endpoint))
            else:
                all_up = False
                try:
                    if apiext_status['detail']['service_states']:
                        all_up = True
                        for service in apiext_status['detail']['service_states']:
                            if not service['status']:
                                logger.debug("service ("+str(service['servicename'])+") is down")
                                all_up = False
                except Exception as err:
                    logger.warn("could not detect service states (yet) - failing operation")
                if not all_up:
                    httpcode = 503
                    raise Exception("one or more services not ready/available")
                else:
                    logger.debug("pre-flight: all services marked as up, ready to service operations")

        except Exception as err:        
            logger.error(str(err))
            return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
            httpcode = return_object['httpcode']
            return(json.dumps(return_object, indent=4), httpcode)

    @flask_app.teardown_request
    def teardown_session(exception=None):
        logger.debug("AFTER")

# service funcs (must be here)
def createService(sname, config):
    global application
    flask_site = WSGIResource(reactor, reactor.getThreadPool(), application=application)
    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
    return (anchore_engine.services.common.createServiceAPI(root, sname, config))


def initializeService(sname, config):
    return (anchore_engine.services.common.initializeService(sname, config))


def registerService(sname, config):
    return (anchore_engine.services.common.registerService(sname, config))

