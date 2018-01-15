"""
Utilities for service discovery. Basic methods are lookup and return of a list of endpoints given a service name.
Will use the local config as authority if entry is found or defer to the database for a lookup if necessary.

"""

import re
from anchore_engine.configuration import localconfig
from anchore_engine.db import db_services, session_scope
from anchore_engine.subsys import logger

def get_endpoints(service_name):
    """
    Return a list of endpoint urls for the given service name.
    :param service_name:
    :return: list of url strings
    """

    local_conf = localconfig.get_config()
    urls = []

    try:
        if service_name + '_endpoint' in local_conf:
            urls = [re.sub("/+$", "", local_conf[service_name + '_endpoint'])]
        else:
            with session_scope() as dbsession:
                service_reports = db_services.get_byname(service_name, session=dbsession)
                if service_reports:
                    for service in service_reports:
                        base_url = service.get('base_url')
                        if base_url:
                            apiversion = service.get('version', '')
                            urls.append('/'.join([base_url, apiversion]))
                        else:
                            raise Exception("cannot load valid endpoint from DB for service {}".format(service_name))

            if not urls:
                raise Exception("cannot locate registered service in DB: " + service_name)
    except Exception as err:
        logger.exception('Error during endpoint lookup for service {}'.format(service_name))
        raise Exception("could not find valid endpoint - exception: " + str(err))

    return urls

