import connexion
import traceback
import uuid
from anchore_engine.db import end_session
from flask import g

SWAGGER_DIR = 'swagger/'
SWAGGER_FILE = 'swagger.yaml'

try:
    # Setup the api server and routing defined by the swagger file
    # Uses the x-swagger-router-controller directive to set which module handles the routes
    application = connexion.FlaskApp(__name__, specification_dir=SWAGGER_DIR)
    application.add_api(SWAGGER_FILE)
except:
    traceback.print_exc()
    raise

# Do some log config etc.
flask_app = application.app

@flask_app.before_request
def setup_session():
    """
    Preflight operation to set a request-specific db session into the request-global context.

    :return:
    """
    #flask_app.logger.debug('Setting up session on request init')
    return

@flask_app.teardown_request
def teardown_session(exception=None):
    """
    Teardown function to ensure no leaked db session prior to request termination.

    :param exception:
    :return:
    """

    flask_app.logger.debug('Session teardown on request teardown')
    end_session()

