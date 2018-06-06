import random

import anchore_engine.clients.common
from anchore_engine.subsys.discovery import get_endpoints
from .generated import DefaultApi, configuration, ApiClient
from anchore_engine.subsys import logger

SERVICE_NAME = 'policy_engine'

def get_client(host=None, user=None, password=None, verify_ssl=True):
    """
    Returns an initialize client withe credentials and endpoint set properly

    :param host: hostname including port for the destination, will be looked up if not provided
    :param user: username for the request auth
    :param password: password for the request auth
    :return: initialized client object
    """

    if not host:
        try:
            endpoint = anchore_engine.clients.common.get_service_endpoint((user, password), SERVICE_NAME)
            if endpoint:
                host = endpoint
            else:
                raise Exception("cannot find endpoint for service: {}".format(SERVICE_NAME))
        except Exception as err:
            raise err

    config = configuration.Configuration()
    if host:
        config.host = host
    if user:
        config.username = user
    if password:
        config.password = password
    config.verify_ssl = verify_ssl
    
    a = ApiClient(configuration=config)
    c = DefaultApi(api_client=a)

    #configuration.api_client = None    

    return c
