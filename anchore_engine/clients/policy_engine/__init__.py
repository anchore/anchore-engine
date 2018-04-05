from anchore_engine.clients import catalog
from .generated import DefaultApi, configuration

SERVICE_NAME = 'policy_engine'


def get_client(host=None, user=None, password=None, verify_ssl=True):
    """
    Returns an initialize client withe credentials and endpoint set properly

    :param host: hostname including port for the destination, will be looked up if not provided
    :param user: username for the request auth
    :param password: password for the request auth
    :return: initialized client object
    """

    if host:
        configuration.host = host
    else:
        try:
            service = catalog.choose_service((user, password), SERVICE_NAME)
            if service:
                host = '/'.join([service['base_url'], service['version']])
            else:
                raise Exception("cannot find endpoint for service: {}".format(SERVICE_NAME))
        except Exception as err:
            raise err

    configuration.verify_ssl = verify_ssl
    configuration.api_client = None
    c = DefaultApi()
    c.api_client.configuration.host = host
    c.api_client.configuration.username = user
    c.api_client.configuration.password = password
    return c
