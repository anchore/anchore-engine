"""
api_utils is a module for common anchore api handling functions useful for all/any anchore-engine api
"""
from OpenSSL import crypto

from anchore_engine.subsys import logger

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
