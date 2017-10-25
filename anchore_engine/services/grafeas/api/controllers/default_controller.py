import connexion

import anchore_engine.clients.catalog
import anchore_engine.services.common
from anchore_engine.subsys import logger


def status():
    httpcode = 500
    try:
        return_object = {
            'busy':False,
            'up':True,
            'message': 'all good'
        }
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)
