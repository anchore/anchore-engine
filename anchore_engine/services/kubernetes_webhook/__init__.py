import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
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
    return(anchore_engine.services.common.initializeService(sname, config))

def registerService(sname, config):
    return(anchore_engine.services.common.registerService(sname, config))
