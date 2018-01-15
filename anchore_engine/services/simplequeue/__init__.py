import os
import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common
import anchore_engine.subsys.simplequeue

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
    try:
        myconfig = config['services'][sname]
    except Exception as err:
        raise err

    for q in ['images_to_analyze', 'error_events']:
        anchore_engine.subsys.simplequeue.create_queue(q)

    for st in anchore_engine.services.common.subscription_types:
        anchore_engine.subsys.simplequeue.create_queue(st)

    return(True)

def registerService(sname, config):
    return(anchore_engine.services.common.registerService(sname, config, enforce_unique=False))
    
