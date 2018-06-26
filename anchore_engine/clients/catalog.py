import json
import hashlib
import urllib

from anchore_engine.clients import http
import anchore_engine.configuration.localconfig
import anchore_engine.services.common
import anchore_engine.clients.common
from anchore_engine.subsys import logger
from anchore_engine.subsys.events import Event

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
        url = base_url + "/registry_lookup?{}".format(urllib.urlencode({'digest': digest}))
    elif tag:
        url = base_url + "/registry_lookup?{}".format(urllib.urlencode({'tag': tag}))
    else:
        logger.error("no input (tag=, digest=)")
        raise Exception("bad input")

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def add_repo(userId, regrepo=None, autosubscribe=False, lookuptag=None):
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
    params = {}
    params['regrepo'] = str(regrepo)
    params['autosubscribe'] = str(autosubscribe)
    if lookuptag:
        params['lookuptag'] = str(lookuptag)

    if params:
        url = url + "?{}".format(urllib.urlencode(params))

    ret = http.anchy_post(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)    

def add_image(userId, tag=None, dockerfile=None, annotations={}):
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
        url = url + "?{}".format(urllib.urlencode({'tag': tag}))
        if dockerfile:
            payload['dockerfile'] = dockerfile

        if annotations:
            payload['annotations'] = annotations

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
        url = url + "?{}".format(urllib.urlencode({'tag': tag, 'history': str(history), 'registry_lookup': str(registry_lookup)}))
    elif digest:
        url = url + "?{}".format(urllib.urlencode({'digest': digest, 'history': str(history), 'registry_lookup': str(registry_lookup)}))
    elif imageId:
        url = url + "?{}".format(urllib.urlencode({'imageId': imageId, 'history': str(history), 'registry_lookup': str(registry_lookup)}))

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
        url = url+"?{}".format(urllib.urlencode({'force': True}))

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

    policy_records = list_policies(userId, active=True)
    for policy_record in policy_records:
        if policy_record['active']:
            return(policy_record)

    return({})

def get_policy(userId, policyId):
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
    url = base_url + "/policies/" + policyId

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)


def list_policies(userId, active=None):
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
    if active is not None:
        params = {'active': active}
    else:
        params = None

    url = base_url + "/policies"

    ret = http.anchy_get(url, auth=auth, params=params, headers=headers, verify=localconfig['internal_ssl_verify'])

    return (ret)

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
    url = base_url + "/policies/" + policyId

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
    url = base_url + "/policies/{}?{}".format(policyId, urllib.urlencode({'cleanup_evals': str(cleanup_evals)}))

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)


def get_evals(userId, policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False):
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

    params = {}
    if policyId:
        params["policyId"] = policyId
    if imageDigest:
        params["imageDigest"] = imageDigest
    if evalId:
        params["evalId"] = evalId
    if tag:
        params["tag"] = tag
    if newest_only:
        params["newest_only"] = newest_only

    ret = http.anchy_get(url, params=params, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_eval_latest(userId, policyId=None, imageDigest=None, tag=None, evalId=None):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    eval_records = get_evals(userId, policyId=policyId, imageDigest=imageDigest, tag=tag, evalId=evalId, newest_only=True)
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
        params = {}
        if subscription_key:
            params['subscription_key'] = subscription_key
        if subscription_type:
            params['subscription_type'] = subscription_type
        if params:
            url = url + "?{}".format(urllib.urlencode(params))

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

def add_registry(userId, registrydata, validate=True):
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
    url = "{}/system/registries?validate={}".format(base_url, validate)

    payload = registrydata

    ret = http.anchy_post(url, data=json.dumps(payload), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def update_registry(userId, registry, registrydata, validate=True):
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
    url = "{}/system/registries/{}?validate={}".format(base_url, registry, validate)

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

def add_event(userId, event):
    if not isinstance(event, Event):
        raise TypeError('Invalid event definition')

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

    ret = http.anchy_post(url, data=event.to_json(), auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_events(userId, source_servicename=None, source_hostid=None, resource_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
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

    path_params = []

    if source_servicename:
        path_params.append('source_servicename={}'.format(source_servicename))

    if source_hostid:
        path_params.append('source_hostid={}'.format(source_hostid))

    if resource_type:
        path_params.append('resource_type={}'.format(resource_type))

    if resource_id:
        path_params.append('resource_id={}'.format(resource_id))

    if level:
        path_params.append('level={}'.format(level))

    if since:
        path_params.append('since={}'.format(since))

    if before:
        path_params.append('before={}'.format(before))

    if page is not None:
        path_params.append('page={}'.format(page))

    if limit is not None:
        path_params.append('limit={}'.format(limit))

    if path_params:
        url = url + '?' + '&'.join(path_params)

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_events(userId, since=None, before=None, level=None):
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

    path_params = []

    if since:
        path_params.append('since={}'.format(since))

    if before:
        path_params.append('before={}'.format(before))

    if level:
        path_params.append('level={}'.format(level))

    if path_params:
        url = url + '?' + '&'.join(path_params)

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def get_event(userId, eventId):
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
    url = base_url + "/events/" + eventId

    ret = http.anchy_get(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

    return(ret)

def delete_event(userId, eventId):
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
    url = base_url + "/events/" + eventId

    ret = http.anchy_delete(url, auth=auth, headers=headers, verify=localconfig['internal_ssl_verify'])

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
    url = base_url + "/system/prune/"+resourcetype
    params = {}
    params['dangling'] = str(dangling)
    if olderthan:
        params['olderthan'] = str(int(olderthan))
    if params:
        url = url + "?{}".format(urllib.urlencode(params))
        
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
