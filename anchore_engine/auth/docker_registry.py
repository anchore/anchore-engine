import json
import re
import time

import docker
import requests

import anchore_engine.configuration.localconfig
import anchore_engine.auth.common
from anchore_engine.subsys import logger
from .skopeo_wrapper import get_image_manifest_skopeo, get_repo_tags_skopeo

docker_clis = {}
docker_cli_unauth = None

def get_authenticated_cli(userId, registry, registry_creds=[]):
    global docker_cli_unauth, docker_clis

    logger.debug("DOCKER CLI: entering auth cli create/fetch for input user/registry: " + str(userId) + " / " + str(registry))

    localconfig = anchore_engine.configuration.localconfig.get_config()

    if not userId:
        if not docker_cli_unauth:
            docker_cli_unauth = docker.Client(base_url=localconfig['docker_conn'], version='auto', timeout=int(localconfig['docker_conn_timeout']))
        logger.debug("DOCKER CLI: returning unauth client")
        return(docker_cli_unauth)
        
    if userId in docker_clis and registry in docker_clis[userId]:
        if 'registry_creds' in docker_clis[userId][registry] and registry_creds == docker_clis[userId][registry]['registry_creds']:
            logger.debug("DOCKER CLI: found existing authenticated CLI")
            return(docker_clis[userId][registry]['cli'])

        else:
            logger.debug("DOCKER CLI: detected cred change, will refresh CLI")

    logger.debug("DOCKER CLI: making new auth CLI for user/registry: " + str(userId) + " / " + str(registry))
    try:

        if userId not in docker_clis:
            docker_clis[userId] = {}

        if registry not in docker_clis[userId]:
            docker_clis[userId][registry] = {}

        user = pw = None
        for registry_record in registry_creds:
            if registry_record['registry'] == registry:
                user, pw = anchore_engine.auth.common.get_docker_registry_userpw(registry_record)

        if not user or not pw:
            logger.debug("DOCKER CLI: making unauth CLI")
            docker_clis[userId][registry]['cli'] = docker.Client(base_url=localconfig['docker_conn'], version='auto', timeout=int(localconfig['docker_conn_timeout']))
            docker_clis[userId][registry]['registry_creds'] = []
        else:
            logger.debug("DOCKER CLI: making auth CLI")
            try:
                cli = docker.Client(base_url=localconfig['docker_conn'], version='auto', timeout=int(localconfig['docker_conn_timeout']))
                rc = cli.login(user, password=pw, registry=registry, reauth=False)
                docker_clis[userId][registry]['cli'] = cli
                docker_clis[userId][registry]['registry_creds'] = registry_creds

            except Exception as err:
                logger.error("DOCKER CLI auth err: " + str(err))
                raise err

    except Exception as err:
        logger.error("DOCKER CLI: unable to get docker cli - exception: " + str(err))
        raise err
    
    if userId in docker_clis and registry in docker_clis[userId]:
        logger.debug("DOCKER CLI: returning auth client")
        return(docker_clis[userId][registry]['cli'])

    logger.error("DOCKER CLI: unable to complete authenticated client create/fetch")
    raise Exception("DOCKER CLI: unable to complete authenticated client create/fetch")

    return(None)

def get_image_manifest_docker_registry(url, registry, repo, tag, user=None, pw=None, verify=True):
    manifest = {}
    digest = ""

    timeout = 30.0
    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        get_manifest_template = "https://"+registry+"/v2/{repository}/manifests/{tag}"
        #get_manifest_template = url+"/v2/{repository}/manifests/{tag}"
        url = get_manifest_template.format(repository=repo, tag=tag)

        try:
            headers = {
                #"Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"
                "Accept": "application/vnd.docker.distribution.manifest.v2+json"
            }

            r = requests.get(url, headers=headers,json=True, auth=authy, verify=verify, timeout=timeout)
            if r.status_code == 200:
                try:
                    manifest = r.json()
                except Exception as err:
                    raise Exception("cannot load manifest from server response - exception: " + str(err))

                try:
                    digest = r.headers['Docker-Content-Digest']
                except Exception as err:
                    raise Exception("cannot find digest in response header (Docker-Content-Digest) - exception: " + str(err))
                
                if manifest['schemaVersion'] == 1:
                    raise Exception("cannot infer digest from response with manifest schemaVersion 1")

            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=("+str(registry)+") repo=("+str(repo)+") tag=("+str(tag)+") user=("+str(user)+")")
            else:
                try:
                    rawtext = str(r.text)
                except:
                    rawtext = ""
                raise Exception("got bad code ("+str(r.status_code)+") from authenticated manifest request: " + str(rawtext))

        except Exception as err:
            raise err
            
    except Exception as err:
        raise err

    return(manifest, digest)

def ping_docker_registry_v2(base_url, u, p, verify=True):
    httpcode = 500
    message = "unknown failure"

    timeout = 30.0
    try:
        # base_url is of the form 'https://index.docker.io' or 'https://mydocker.com:5000' <-- note: https only, no trailing slash, etc
        index_url = "{}/v2".format(base_url)
        try:
            r = requests.get(index_url, verify=verify, allow_redirects=True, timeout=timeout)
        except Exception as err:
            httpcode = 500
            raise err
        try:
            if r.status_code in [404]:
                r = requests.get(index_url+'/', verify=verify, allow_redirects=True, timeout=timeout)
            if r.status_code not in [200, 401]:
                httpcode = 400
                raise Exception("cannot access registry using registry version 2 {}".format(index_url))
        except Exception as err:
            raise err

        if u and p:
            auth_url = None
            try:
                for hkey in r.headers.keys():
                    if hkey.lower() == "www-authenticate":
                        www_auth = r.headers.get(hkey)
                        (www_auth_type, www_auth_raw) = re.match("(.*?) +(.*)", www_auth).groups()
                        if www_auth_type == 'Bearer':
                            raw_keyvals = www_auth_raw.split(",")
                            for keyval in raw_keyvals:
                                key, val = keyval.split('=', 2)
                                if key.lower() == 'realm':
                                    auth_url = val.replace('"', '')
                        elif www_auth_type == 'Basic':
                            auth_url = index_url
                        else:
                            auth_url = index_url
                if not auth_url:
                    httpcode = 400
                    raise Exception("could not retrieve an auth URL from response")
            except Exception as err:
                raise err

            try:
                r = requests.get(auth_url, auth=(u, p), verify=verify, timeout=timeout)
            except Exception as err:
                httpcode = 500
                raise err

            try:
                if r.status_code in [404]:
                    r = requests.get(auth_url+'/', auth=(u, p), verify=verify, timeout=timeout)
                if r.status_code not in [200]:
                    httpcode = 401
                    raise Exception("cannot login to registry user={} registry={} - invalid username/password".format(u, base_url))
            except Exception as err:
                raise err

            httpcode = 200
            message = "login successful"
        else:
            httpcode = 200
            message = "no credentials supplied - assuming anonymous"
    except Exception as err:
        message = "{}".format(err)

    return(httpcode, message)

def ping_docker_registry(registry_record):
    ret = False
    user = ''
    url = ''

    try:
        registry = registry_record['registry']
        verify = registry_record['registry_verify']
        if registry in ['docker.io']:
            url = "https://index.docker.io"
        else:
            url = "https://" + registry

        user, pw = anchore_engine.auth.common.get_docker_registry_userpw(registry_record)
    
        httpcode, message = ping_docker_registry_v2(url, user, pw, verify=verify)
        if httpcode != 200:
            raise Exception("{}".format(message))

        logger.debug("registry check successful: registry={} user={} code={} message={}".format(registry, user, httpcode, message))
        ret = True
    except Exception as err:
        logger.warn("failed check to access registry ("+str(url)+","+str(user)+") - exception: " + str(err))
        raise Exception("failed check to access registry ("+str(url)+","+str(user)+") - exception: " + str(err))        

    return(ret)


def get_repo_tags(userId, image_info, registry_creds=None):
    user = pw = None
    registry_verify=True

    registry = image_info['registry']
    try:
        user, pw, registry_verify = anchore_engine.auth.common.get_creds_by_registry(registry, registry_creds=registry_creds)
    except Exception as err:
        raise err    

    if registry == 'docker.io':
        url = "https://index.docker.io"
        if not re.match(".*/.*", image_info['repo']):
            repo = "library/"+image_info['repo']
        else:
            repo = image_info['repo']
    else:
        url = "https://"+registry
        repo = image_info['repo']

    lookuptag = 'latest'
    if image_info['tag']:
        lookuptag = image_info['tag']

    alltags = get_repo_tags_skopeo(url, registry, repo, lookuptag=lookuptag, user=user, pw=pw, verify=registry_verify)
        
    return(alltags)

def get_image_manifest(userId, image_info, registry_creds):
    logger.debug("get_image_manifest input: " + str(userId) + " : " + str(image_info) + " : " + str(time.time()))
    user = pw = None
    repo = url = None
    registry_verify=True

    registry = image_info['registry']
    try:
        user, pw, registry_verify = anchore_engine.auth.common.get_creds_by_registry(registry, registry_creds=registry_creds)
    except Exception as err:
        raise err    

    if registry == 'docker.io':
        url = "https://index.docker.io"
        if not re.match(".*/.*", image_info['repo']):
            repo = "library/"+image_info['repo']
        else:
            repo = image_info['repo']
    else:
        url = "https://"+registry
        repo = image_info['repo']

    if image_info['digest']:
        tag = None
        input_digest = image_info['digest']
        fulltag = "{}/{}@{}".format(registry, repo, input_digest)
    else:
        input_digest = None
        tag = image_info['tag']
        fulltag = "{}/{}:{}".format(registry, repo, tag)

    manifest = digest = None

    logger.debug("trying to get manifest/digest for image ("+str(fulltag)+")")
    err = None
    try:
        if tag:
            manifest, digest = get_image_manifest_skopeo(url, registry, repo, intag=tag, user=user, pw=pw, verify=registry_verify)
        elif input_digest:
            manifest, digest = get_image_manifest_skopeo(url, registry, repo, indigest=input_digest, user=user, pw=pw, verify=registry_verify)
        else:
            raise Exception("neither tag nor digest was given as input")
    except Exception as err:
        logger.error("could not fetch manifest/digest: " + str(err))
        manifest = digest = None

    if manifest and digest:
        return(manifest, digest)
    
    logger.error("could not get manifest/digest for image ({}) from registry ({}) - error: {}".format(fulltag, url, err))
    raise Exception("could not get manifest/digest for image ({}) from registry ({}) - error: {}".format(fulltag, url, err))

    return({}, "")

