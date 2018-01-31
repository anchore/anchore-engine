import json
import re
import hashlib
import time
import copy
import random

from anchore_engine.clients import http
import anchore_engine.configuration.localconfig
from anchore_engine import db
from anchore_engine.db import db_services
import anchore_engine.services.common
import anchore_engine.clients.common
from anchore_engine.subsys import logger

localconfig = None
headers = {'Content-Type': 'application/json'}

def lookup_registry_image(userId, tag=None, digest=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    if digest:
        url = base_url + "/registry_lookup?digest=" + digest
    elif tag:
        url = base_url + "/registry_lookup?tag=" + tag
    else:
        logger.error("no input (tag=, digest=)")
        raise Exception("bad input")

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_repo(userId, regrepo=None, autosubscribe=False):
    global localconfig, headers

    if not regrepo:
        raise Exception("no regrepo supplied as input")

    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')

    url = base_url + "/repo"
    url = url + "?regrepo="+regrepo+"&autosubscribe="+str(autosubscribe)

    ret = http.anchy_post(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def add_image(userId, tag=None, dockerfile=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')

    url = base_url + "/image"

    payload = {}
    if tag:
        url = url + "?tag="+tag
        if dockerfile:
            payload['dockerfile'] = dockerfile

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_imagetags(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/summaries/imagetags"

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)        

def get_image(userId, tag=None, digest=None, imageId=None, imageDigest=None, registry_lookup=False, history=False):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/image"

    if imageDigest:
        url = base_url + "/image/" + imageDigest
    elif tag:
        url = url + "?tag=" + tag
        url = url + "&history="+str(history)+"&registry_lookup="+str(registry_lookup)
    elif digest:
        url = url + "?digest=" + digest
        url = url + "&history="+str(history)+"&registry_lookup="+str(registry_lookup)
    elif imageId:
        url = url + "?imageId=" + imageId
        url = url + "&history="+str(history)+"&registry_lookup="+str(registry_lookup)

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def update_image(userId, imageDigest, image_record={}):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}
   
    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
 
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')

    url = base_url + "/image/" + imageDigest

    payload = {}
    payload.update(image_record)

    ret = http.anchy_put(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_image(userId, imageDigest, force=False):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/image/" + imageDigest

    if force:
        url = url+"?force=True"

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def import_image(userId, anchore_data):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/import"

    payload = anchore_data

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_policy(userId, bundle):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}
   
    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
 
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/policies"

    try:
        payload = anchore_engine.services.common.make_policy_record(userId, bundle)
    except Exception as err:
        logger.error("couldn't prep input as valid policy add payload: " + str(err))
        raise err

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def get_active_policy(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    policy_records = get_policy(userId)
    for policy_record in policy_records:
        if policy_record['active']:
            return(policy_record)

    return({})

def get_policy(userId, policyId=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/policies"

    payload = {}
    if policyId:
        payload["policyId"] = policyId

    ret = http.anchy_get(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def update_policy(userId, policyId, policy_record={}):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/policies"

    payload = policy_record

    ret = http.anchy_put(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def delete_policy(userId, policyId=None, cleanup_evals=True):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/policies?cleanup_evals="+str(cleanup_evals)

    payload = {}
    if policyId:
        payload["policyId"] = policyId

    ret = http.anchy_delete(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_eval(userId, policyId=None, imageDigest=None, tag=None, evalId=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/evals"

    payload = {}
    if policyId:
        payload["policyId"] = policyId
    if imageDigest:
        payload["imageDigest"] = imageDigest
    if evalId:
        payload["evalId"] = evalId
    if tag:
        payload["tag"] = tag

    ret = http.anchy_get(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_eval_latest(userId, policyId=None, imageDigest=None, tag=None, evalId=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    eval_records = get_eval(userId, policyId=policyId, imageDigest=imageDigest, tag=tag, evalId=evalId)
    if eval_records:
        return(eval_records[0])
    return({})

def add_eval(userId, evalId, policyId, imageDigest, tag, final_action, eval_url):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/evals"

    try:
        payload = anchore_engine.services.common.make_eval_record(userId, evalId, policyId, imageDigest, tag, final_action, eval_url)
    except Exception as err:
        logger.error("couldn't prep input as valid eval add payload: " + str(err))
        raise err

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def get_subscription(userId, subscription_id=None, subscription_key=None, subscription_type=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/subscriptions"
    if subscription_id:
        url = url + "/" + subscription_id
    elif subscription_key or subscription_type:
        url = url + "?"
        if subscription_key:
            url = url + "subscription_key="+subscription_key+"&"
        if subscription_type:
            url = url + "subscription_type="+subscription_type+"&"

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_subscription(userId, subscription_key=None, subscription_type=None, subscription_id=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    if subscription_key and subscription_type:
        subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/subscriptions/" + subscription_id

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def update_subscription(userId, subscriptiondata, subscription_type=None, subscription_key=None, subscription_id=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    if subscription_key and subscription_type:
        subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type])).hexdigest()

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/subscriptions/" + subscription_id

    ret = http.anchy_put(url, data=json.dumps(subscriptiondata), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_subscription(userId, payload):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/subscriptions"

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_subscription_types(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/subscriptions"

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

def get_users(auth):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(auth) == tuple:
        ruserId, rpw = auth
    else:
        ruserId = auth
        rpw = ""
    auth = (ruserId, rpw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/users"

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_user(auth, userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(auth) == tuple:
        ruserId, rpw = auth
    else:
        ruserId = auth
        rpw = ""
    auth = (ruserId, rpw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/users/"+userId

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_document(userId, bucket, name):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = ""

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/archive/" + bucket + "/" + name

    archive_document = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])
    ret = archive_document['document']

    return(ret)

def put_document(userId, bucket, name, inobj):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/archive/" + bucket + "/" + name
    
    payload = {}
    payload['document'] = inobj

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_service(userId, servicename=None, hostid=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/services"
    if servicename:
        url = url + "/" + servicename
        if hostid:
            url = url + "/" + hostid

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_service(userId, servicename=None, hostid=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    if not servicename or not hostid:
        raise Exception("invalid input - must specify a servicename and hostid to delete")

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/services/" + servicename + "/" + hostid

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_registry(userId, registry=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/registries"
    if registry:
        url = url + "/" + registry

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_registry(userId, registrydata):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/registries"

    payload = registrydata

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def update_registry(userId, registry, registrydata):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)
    
    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/registries/" + registry

    payload = registrydata

    ret = http.anchy_put(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_registry(userId, registry=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    if not registry:
        raise Exception("invalid input - must specify a registry to delete")

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/registries/" + registry

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_event(userId, hostId, service_name, level, message, detail=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/events"
    
    payload = {
        'hostId':hostId,
        'service_name':service_name,
        'level':level,
        'message':message,
        'detail':detail
    }

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_event(userId, hostId=None, level=None, message=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/events"
    
    payload = {
        'hostId':hostId,
        'level':level,
        'message':message
    }

    ret = http.anchy_get(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_prune_resourcetypes(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/prune"
    
    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_prune_candidates(userId, resourcetype, dangling=True, olderthan=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/prune/"+resourcetype+"?dangling="+str(dangling)
    if olderthan:
        url = url + "&olderthan="+str(int(olderthan))
    
    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def perform_prune(userId, resourcetype, prune_candidates):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    base_url = anchore_engine.clients.common.get_service_endpoint(userId, 'catalog')
    url = base_url + "/system/prune/"+resourcetype

    payload = json.dumps(prune_candidates)

    ret = http.anchy_post(url, data=payload, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)
