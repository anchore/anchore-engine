import re
import json
import traceback

import connexion
from connexion import request
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.web.resource import Resource
from twisted.web import rewrite
from twisted.internet.task import LoopingCall

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
from anchore_engine.subsys import logger

_default_api_version = "v1"
servicename = 'apiext'

def default_version_rewrite(request):
    global _default_api_version
    try:
        if request.postpath:
            if request.postpath[0] != 'health' and request.postpath[0] != _default_api_version:
                request.postpath.insert(0, _default_api_version)
                request.path = '/'+_default_api_version+request.path
    except Exception as err:
        logger.error("rewrite exception: " +str(err))
        raise err

# service funcs (must be here)
def createService(sname, config):
    global monitor_threads, monitors, servicename

    try:
        application = connexion.FlaskApp(__name__, specification_dir='swagger/')
        flask_app = application.app
        flask_app.url_map.strict_slashes = False
        anchore_engine.subsys.metrics.init_flask_metrics(flask_app, servicename=servicename)
        application.add_api('swagger.yaml', validate_responses=False)
    except Exception as err:
        traceback.print_exc()
        raise err

    try:
        myconfig = config['services'][sname]
        servicename = sname
    except Exception as err:
        raise err

    try:
        kick_timer = int(myconfig['cycle_timer_seconds'])
    except:
        kick_timer = 1

    doapi = False
    try:
        if myconfig['listen'] and myconfig['port'] and myconfig['endpoint_hostname']:
            doapi = True
    except:
        doapi = False

    kwargs = {}
    kwargs['kick_timer'] = kick_timer
    kwargs['monitors'] = monitors
    kwargs['monitor_threads'] = monitor_threads
    kwargs['servicename'] = servicename

    if doapi:
        # start up flask service
        
        flask_site = WSGIResource(reactor, reactor.getThreadPool(), application=flask_app)
        realroot = Resource()
        realroot.putChild(b"v1", anchore_engine.services.common.getAuthResource(flask_site, sname, config))
        realroot.putChild(b"health", anchore_engine.services.common.HealthResource())
        # this will rewrite any calls that do not have an explicit version to the base path before being processed by flask
        root = rewrite.RewriterResource(realroot, default_version_rewrite)
        ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

        # start up the monitor as a looping call
        lc = LoopingCall(anchore_engine.services.common.monitor, **kwargs)
        lc.start(1)
    else:
        # start up the monitor as a timer service
        svc = internet.TimerService(1, anchore_engine.services.common.monitor, **kwargs)
        svc.setName(sname)
        ret_svc = svc

    return (ret_svc)

def initializeService(sname, config):
    return (anchore_engine.services.common.initializeService(sname, config))


def registerService(sname, config):
    rc = anchore_engine.services.common.registerService(sname, config, enforce_unique=False)

    service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, update_db=True)

    return (rc)

# monitor infrastructure

monitors = {
    'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [servicename], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
}
monitor_threads = {}
