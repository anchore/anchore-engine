import os
import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.simplequeue
import anchore_engine.subsys.servicestatus

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    application.app.url_map.strict_slashes = False
    application.add_api('swagger.yaml')
    app = application
except Exception as err:
    traceback.print_exc()
    raise err

queues = {}

# service funcs (must be here)            
def createService(sname, config):
    global app

    flask_site = WSGIResource(reactor, reactor.getThreadPool(), app)
    root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
    return(anchore_engine.services.common.createServiceAPI(root, sname, config))

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

    #for q in ['images_to_analyze', 'error_events']:
    for q in anchore_engine.services.common.queue_names:        
        anchore_engine.subsys.simplequeue.create_queue(q)

    for st in anchore_engine.services.common.subscription_types:
        anchore_engine.subsys.simplequeue.create_queue(st)

    #from anchore_engine.services.catalog import catalog_threads
    #for cs in catalog_threads.keys():
    #    try:
    #        queueName = catalog_threads[cs]['args'][1]
    #        anchore_engine.subsys.simplequeue.create_queue(queueName)
    #    except:
    #        pass

    return(True)

def registerService(sname, config):
    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True)
    return(anchore_engine.services.common.registerService(sname, config, enforce_unique=False))
    
