import traceback

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

# anchore modules
import anchore_engine.services.common

# from klein import Klein
# from flask import Flask, request

#from services.kubernetes_webhook_v1 import api as api_v1
#from services.apitest_v2 import api as api_v2

#app = Flask(__name__)

# load up the APIs
#apis = [
#    (api_v1, '/v1')
#]
#for apiname,prefix in apis:
#    app.register_blueprint(apiname, url_prefix=prefix)

#queues = {}

# default non-api route lists available API version prefixes
#@app.route('/', methods=['GET'])
#def default():
#    ret = []
#    for apiname,prefix in apis:
#        ret.append(prefix)
#    return(json.dumps(ret)+"\n", 200)

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
