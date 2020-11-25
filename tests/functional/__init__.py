import logging

import requests


def get_engine_version(username, password, base_url):
    url = "{}/status".format(base_url)
    r = requests.get(url, auth=(username, password))
    if r.status_code == 200:
        d = r.json()
        return d.get("version", None)
    else:
        raise AssertionError("Error response for version check: {}".format(r))


def get_logger(name):
    return logging.getLogger("conftest.%s" % name)
