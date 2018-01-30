import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.internet.task import LoopingCall

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.servicestatus

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    application.app.url_map.strict_slashes = False
    application.add_api('swagger.yaml')
    flask_app = application
except Exception as err:
    traceback.print_exc()
    raise err

servicename = 'kubernetes_webhook'

# service funcs (must be here)            
def createService(sname, config):
    global flask_app, monitor_threads, monitors, servicename

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

        flask_site = WSGIResource(reactor, reactor.getThreadPool(), flask_app)
        root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
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
#    global app
#
#    flask_site = WSGIResource(reactor, reactor.getThreadPool(), app)
#    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
#    return(anchore_engine.services.common.createServiceAPI(root, sname, config))

def initializeService(sname, config):
    service_record = {'hostid': config['host_id'], 'servicename': sname}
    try:
        if not anchore_engine.subsys.servicestatus.has_status(service_record):
            anchore_engine.subsys.servicestatus.initialize_status(service_record, up=True, available=False, message='initializing')
    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("could not initialize service status - exception: " + str(err))

    return(anchore_engine.services.common.initializeService(sname, config))

def registerService(sname, config):
    rc = anchore_engine.services.common.registerService(sname, config, enforce_unique=False)

    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, update_db=True)

    return (rc)
#    service_record = {'hostid': config['host_id'], 'servicename': sname}
#    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True)
#    return(anchore_engine.services.common.registerService(sname, config, enforce_unique=False))

# monitor infrastructure

monitors = {
    'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [servicename], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
}
monitor_threads = {}
