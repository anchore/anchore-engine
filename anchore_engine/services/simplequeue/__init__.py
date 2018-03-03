import os
import time
import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.web.resource import Resource
from twisted.web import rewrite
from twisted.internet.task import LoopingCall
from twisted import internet

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.simplequeue
import anchore_engine.subsys.servicestatus
from anchore_engine.subsys import logger
import anchore_engine.subsys.metrics

servicename = 'simplequeue'
_default_api_version = "v1"


# A regular queue configuration with no extra features enabled
default_queue_config = {
    'max_outstanding_messages': -1,
    'visibility_timeout': 0
}

# From services.common, is only used for service init
#queue_names = ['images_to_analyze', 'error_events', 'watcher_tasks', 'feed_sync_tasks']
# Replaces the above with configuration options for each queue
queues_to_bootstrap = {
    'images_to_analyze': default_queue_config,
    'error_events': default_queue_config,
    'watcher_tasks': default_queue_config,
    'feed_sync_tasks': {
        'max_outstanding_messages': 1,
        'visibility_timeout': 3600  # Default 1 hour timeout for messages outstanding
        }
    }

queues = {}

# service funcs (must be here)            

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

def createService(sname, config):
    global monitor_threads, monitors, servicename

    try:
        application = connexion.FlaskApp(__name__, specification_dir='swagger/')
        flask_app = application.app
        flask_app.url_map.strict_slashes = False
        anchore_engine.subsys.metrics.init_flask_metrics(flask_app, servicename=servicename)
        application.add_api('swagger.yaml')
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
        #root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
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
    
    service_record = {'hostid': config['host_id'], 'servicename': sname}
    try:
        if not anchore_engine.subsys.servicestatus.has_status(service_record):
            anchore_engine.subsys.servicestatus.initialize_status(service_record, up=True, available=False, message='initializing')
    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("could not initialize service status - exception: " + str(err))

    try:
        myconfig = config['services'][sname]
    except Exception as err:
        raise err

    for st in anchore_engine.services.common.subscription_types:
        if st not in queues_to_bootstrap:
            queues_to_bootstrap[st] = default_queue_config

    for qname, config in queues_to_bootstrap.iteritems():
        anchore_engine.subsys.simplequeue.create_queue(name=qname, max_outstanding_msgs=config.get('max_outstanding_messages', -1), visibility_timeout=config.get('visibility_timeout', 0))
    return(True)

def registerService(sname, config):
    rc = anchore_engine.services.common.registerService(sname, config, enforce_unique=False)

    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, update_db=True)

    return (rc)

# monitors

def handle_metrics(*args, **kwargs):

    cycle_timer = kwargs['mythread']['cycle_timer']
    while(True):
        try:
            for qname in anchore_engine.subsys.simplequeue.get_queuenames():
                try:
                    qlen = anchore_engine.subsys.simplequeue.qlen(qname)
                    anchore_engine.subsys.metrics.gauge_set("anchore_queue_length", qlen, queuename=qname)
                except:
                    logger.warn("could not get/set queue length metric for queue ("+str(qname)+")")
        except Exception as err:
            logger.warn("handler failed - exception: " + str(err))

        time.sleep(cycle_timer)

    return(True)
    
# monitor infrastructure

monitors = {
    'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [servicename], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'handle_metrics': {'handler': handle_metrics, 'taskType': 'handle_metrics', 'args': [servicename], 'cycle_timer': 15, 'min_cycle_timer': 15, 'max_cycle_timer': 15, 'last_queued': 0, 'last_return': False, 'initialized': False},
}
monitor_threads = {}
