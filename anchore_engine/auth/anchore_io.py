import anchore_engine.configuration.localconfig

from anchore_engine.clients.feeds.feed_service.feeds import Oauth2AuthenticatedClient
from anchore_engine.utils import AnchoreException

anchoreio_clients = {}

def get_anchoreio_client(user, pw):
    global anchoreio_clients

    if user in anchoreio_clients:
        if pw == anchoreio_clients[user].get('pw', None) and anchoreio_clients[user].get('client', None):
            return(anchoreio_clients[user]['client'])
        else:
            del(anchoreio_clients[user]['client'])
            anchoreio_clients[user] = {}

    # make a new client
    localconfig = anchore_engine.configuration.localconfig.get_config()

    anchoreio_clients[user] = {}
    try:
        anchoreio_clients[user]['pw'] = pw
        anchoreio_clients[user]['client'] = Oauth2AuthenticatedClient(localconfig.get('feeds', {}).get('token_url'), localconfig.get('feeds', {}).get('client_url'), user, pw, connect_timeout=localconfig.get('connection_timeout_seconds', None), read_timeout=localconfig.get('read_timeout_seconds', None))
    except Exception as err:
        anchoreio_clients.pop(user, None)
        raise AnchoreIOClientError(cause=err)

    return(anchoreio_clients[user]['client'])


class AnchoreIOClientError(AnchoreException):
    def __init__(self, cause, msg='Error initializing anchore.io client with configured credentials'):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)

    def __str__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)
