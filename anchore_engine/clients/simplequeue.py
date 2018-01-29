import json
import time
import random

from anchore_engine.clients import catalog
from anchore_engine.clients import http
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger

localconfig = None
headers = {'Content-Type': 'application/json'}

def get_simplequeue_endpoint(userId):
    global localconfig, headers

    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    base_url = ""
    try:
        service = catalog.choose_service(userId, 'simplequeue')
        if not service:
            raise Exception("cannot locate available simplequeue service")

        endpoint = service['service_url']
        if endpoint:
            apiversion = service['version']
            base_url = '/'.join([endpoint, apiversion, 'queues'])
        else:
            raise Exception("cannot load valid endpoint from service record")

    except Exception as err:
        raise Exception("could not find valid simplequeue endpoint - exception: " + str(err))

    return(base_url)

def get_simplequeue_endpoints(userId):
    global localconfig, headers

    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    base_urls = []
    try:
        services = catalog.get_enabled_services(userId, 'simplequeue')
        if not services:
            raise Exception("cannot locate available simplequeue services")

        for service in services:
            endpoint = service['service_url']
            if endpoint:
                apiversion = service['version']
                base_url = '/'.join([endpoint, apiversion, 'queues'])
                base_urls.append(base_url)
            else:
                pass

        if not base_urls:
            raise Exception("cannot load valid endpoint from service record")

    except Exception as err:
        raise Exception("could not find valid simplequeue endpoint - exception: " + str(err))

    return(base_urls)

def get_queues(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    #base_url = get_simplequeue_endpoint(auth)
    #url = '/'.join([base_url])

    #ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    url_postfix = []
    base_urls = get_simplequeue_endpoints(auth)
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return(ret)

def qlen(userId, name):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = 0

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    #base_url = get_simplequeue_endpoint(auth)
    #url = '/'.join([base_url, name, "qlen"])

    #ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    url_postfix = [name, "qlen"]
    base_urls = get_simplequeue_endpoints(auth)
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)
    ret = int(ret)

    return(ret)
    
def enqueue(userId, name, inobj, qcount=0, forcefirst=False):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = inobj

    #base_url = get_simplequeue_endpoint(auth)
    #url = '/'.join([base_url, name])
    #url = url + "?qcount="+str(qcount) + "&forcefirst=" + str(forcefirst)

    #ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    url_postfix = [name, "?qcount="+str(qcount) + "&forcefirst=" + str(forcefirst)]
    base_urls = get_simplequeue_endpoints(auth)
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_post, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return(ret)

def is_inqueue(userId, name, inobj):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = inobj

    #base_url = get_simplequeue_endpoint(auth)
    #url = '/'.join([base_url, name, 'is_inqueue'])

    #ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    url_postfix = [name, 'is_inqueue']
    base_urls = get_simplequeue_endpoints(auth)
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_post, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return(ret)

def dequeue(userId, name):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    #base_url = get_simplequeue_endpoint(auth)
    #url = '/'.join([base_url, name])
    #ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    url_postfix = [name]
    method = http.anchy_get
    base_urls = get_simplequeue_endpoints(auth)
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return(ret)

