"""
api_utils is a module for common anchore api handling functions useful for all/any anchore-engine api
"""
from OpenSSL import crypto
from connexion import request
from collections import namedtuple

from anchore_engine.subsys import logger

AuthenticationContext = namedtuple('AuthenticationContext', field_names=['user_id', 'password'])


def pass_user_context(f):
    """
    A decorator for handling auth info for an api handler to pass AuthenticationContext as the first parameter of the function.
    Useful since connexion/flask doesn't pass header parameters into the handler functions.

    Example:

    @pass_user_context
    def add_image(auth_ctx, image_digest):
      catalog.add_image(user_id=auth_ctx.user_id, image_digest=image_digest)

    :param f:
    :return:
    """
    def decorator(*args, **kwargs):
        if hasattr(request, 'authorization'):
            if hasattr(request.authorization, 'username'):
                user = request.authorization.username
            else:
                user = None
            if hasattr(request.authorization, 'password'):
                passwd = request.authorization.password
            else:
                passwd = None
        else:
            user = None
            passwd = None

        auth_context = AuthenticationContext(user_id=user, password=passwd)
        return f(auth_context, *args, **kwargs)
    return decorator


def _load_ssl_key(path):
    """
    Load a private SSL key
    :param path:
    :return: key content
    """

    try:
        with open(path, 'rt') as f:
            sdata = f.read()
        key_data = crypto.load_privatekey(crypto.FILETYPE_PEM, sdata)
        return key_data
    except Exception as err:
        logger.exception('Error loading ssl key from: {}'.format(path))
        raise err


def _load_ssl_cert(path):
    try:
        with open(path, 'rt') as f:
            sdata = f.read()
        cert_data = crypto.load_certificate(crypto.FILETYPE_PEM, sdata.encode('utf8'))
        return cert_data
    except Exception as err:
        logger.exception('Error loading ssl key from: {}'.format(path))
        raise err
