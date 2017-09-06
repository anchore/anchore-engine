import json
import re
import time

import docker
import requests

import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger
from anchore_engine.vendored import docker_registry_client
from .skopeo_wrapper import get_image_manifest_skopeo

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
                user = registry_record['registry_user']
                pw = registry_record['registry_pass']

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

def get_image_manifest_oauth2(url, registry, repo, tag, user=None, pw=None, verify=True):
    manifest = {}
    digest = ""
    
    try:
        drc = docker_registry_client.DockerRegistryClient(url, username=user, password=pw, verify_ssl=verify, api_version=2)
        r = drc.repository(namespace=None, repository=repo)
        manifest, digest = r.manifest(tag, accept_version=2)

        if manifest['schemaVersion'] == 1:
            raise Exception("cannot infer digest from response with manifest schemaVersion 1")
    except Exception as err:
        raise err

    return(manifest, digest)

def get_image_manifest_docker_registry(url, registry, repo, tag, user=None, pw=None, verify=True):
    manifest = {}
    digest = ""

    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        get_manifest_template = "https://"+registry+"/v2/{repository}/manifests/{tag}"
        url = get_manifest_template.format(repository=repo, tag=tag)

        try:
            headers = {
                #"Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"
                "Accept": "application/vnd.docker.distribution.manifest.v2+json"
            }

            r = requests.get(url, headers=headers,json=True, auth=authy, verify=verify)
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

def get_image_manifest(userId, image_info, registry_creds):
    logger.debug("get_image_manifest input: " + userId + " : " + str(image_info) + " : " + str(time.time()))

    user = pw = None
    registry_verify=True

    registry = image_info['registry']

    try:
        for registry_record in registry_creds:
            if registry_record['registry'] == registry:
                user = registry_record['registry_user']
                pw = registry_record['registry_pass']
                registry_verify = registry_record['registry_verify']
                break
    except:
        pass

    if registry == 'docker.io':
        url = "https://index.docker.io"
        if not re.match(".*/.*", image_info['repo']):
            repo = "library/"+image_info['repo']
        else:
            repo = image_info['repo']
    else:
        url = "https://"+registry
        repo = image_info['repo']

    oauth_err = basicauth_err = skopeoauth_err = "N/A"

    if image_info['digest']:
        pullstring = image_info['digest']
    else:
        pullstring = image_info['tag']

    auth_funcs = [get_image_manifest_oauth2, get_image_manifest_docker_registry, get_image_manifest_skopeo]
    auth_errors = {}
    manifest = digest = None

    for af in auth_funcs:
        manifest = digest = None

        try:
            imagestr = url + "/" + repo + ":" + pullstring
        except:
            imagestr = pullstring

        logger.debug("trying to get manifest/digest for image ("+str(imagestr)+") using ("+str(af.__name__)+")")
        try:
            manifest, digest = af(url, registry, repo, pullstring, user=user, pw=pw, verify=registry_verify)
        except Exception as err:
            logger.debug("could not get manifest/digest for image ("+imagestr+") using ("+str(af.__name__)+") - exception: " + str(err))
            auth_errors[af.__name__] = str(err)
        if manifest and digest:
            break

    if manifest and digest:
        return(manifest, digest)
    
    logger.error("could not get manifest/digest for image using any auth method: ("+str(pullstring)+"): " + str(auth_errors))
    raise Exception("could not get manifest/digest for image using any auth method: ("+str(pullstring)+"): " + str(auth_errors))

    return({}, "")

#####################################################    

def get_image_manifest_dockerhub_orig(repo, tag, user=None, pw=None):
    manifest = {}
    digest = ""
    
    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        #TODO externalize URLs
        auth_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
        url = auth_url.format(repository=repo)
        
        token = ""
        try:
            r = requests.get(url, json=True, auth=authy)
            if r.status_code == 200:
                #token = requests.get(url, json=True, auth=authy).json()["token"]
                token = r.json()["token"]
            elif r.status_code == 402:
                raise Exception("not authorized (401) returned from registry: auth_url=("+str(url)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))
        except Exception as err:
            logger.error("could not get auth token: " + str(err))
            raise err
        
        get_manifest_template = "https://registry.hub.docker.com/v2/{repository}/manifests/{tag}"
        url = get_manifest_template.format(repository=repo, tag=tag)

        try:
            headers = {
                "Authorization": "Bearer {}".format(token),
                "Accept": "application/vnd.docker.distribution.manifest.v2+json"
            }

            r = requests.get(url, headers=headers,json=True)
            if r.status_code == 200:
                manifest = r.json()
                digest = r.headers['Docker-Content-Digest']
            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=(https://registry.hub.docker.com) repo=("+str(repo)+") tag=("+str(tag)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))

        except Exception as err:
            logger.warn("could not get manifest: " + str(err))
            raise err
            
    except Exception as err:
        raise err

    return(manifest, digest)

def get_image_manifest_orig(userId, image_info):
    # first see if registry is DH or not...
    localconfig = anchore_engine.configuration.localconfig.get_config()

    logger.debug("get_image_manifest input: " + userId + " : " + str(image_info) + " : " + str(time.time()))

    user = pw = None
    
    registry = image_info['registry']

    try:
        creds = localconfig['credentials']['users'][userId]['registry_service_auths']['docker'][registry]['auth']
        user,pw = creds.split(":")
    except:
        pass
            
    if registry in ['docker.io', 'container-registry.oracle.com', 'registry.connect.redhat.com']:
        if registry == 'docker.io':
            url = "https://index.docker.io"

            if not re.match(".*/.*", image_info['repo']):
                repo = "library/"+image_info['repo']
            else:
                repo = image_info['repo']
        elif registry == "container-registry.oracle.com":
            url = "https://container-registry.oracle.com"
            repo = image_info['repo']
        elif registry == "registry.connect.redhat.com":
            url = "https://registry.connect.redhat.com"
            repo = image_info['repo']

        if image_info['digest']:
            manifest, digest = get_image_manifest_oauth2(url, repo, image_info['digest'], user=user, pw=pw)
        else:
            manifest, digest = get_image_manifest_oauth2(url, repo, image_info['tag'], user=user, pw=pw)
        
        return(manifest, digest)
    else:
        if image_info['digest']:
            manifest, digest = get_image_manifest_docker_registry(registry, image_info['repo'], image_info['digest'], user=user, pw=pw)
        else:
            manifest, digest = get_image_manifest_docker_registry(registry, image_info['repo'], image_info['tag'], user=user, pw=pw)
        return(manifest, digest)
        
    return({}, "")
    

def get_registry_catalog_docker_orig(registry, user=None, pw=None):
    ret = {}
    
    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        get_manifest_template = "https://"+registry+"/v2/_catalog"
        url = get_manifest_template
        #url = get_manifest_template.format(repository=repo, tag=tag)

        try:
            #headers = {
            #    "Accept": "application/vnd.docker.distribution.manifest.v2+json"
            #}
            headers = {}

            r = requests.get(url, headers=headers,json=True, auth=authy, verify=False)
            if r.status_code == 200:
                ret = r.json()
                #manifest = r.json()
                #digest = r.headers['Docker-Content-Digest']
            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=("+str(registry)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))

        except Exception as err:
            logger.warn("could not get manifest: " + str(err))
            raise err
            
    except Exception as err:
        raise err

    return(ret)

def get_dockerhub_token_orig(user=None, pw=None):
    #export TOKEN=`curl -s -H "Content-Type: application/json" -X POST -d '{"username": "'${UNAME}'", "password": "'${UPASS}'"}' https://hub.docker.com/v2/users/login/ | jq -r .token`
    if user and pw:
        headers = {
            'Content-Type': 'application/json'
        }
        payload = {
            'username': user,
            'password': pw
        }
        url = "https://hub.docker.com/v2/users/login/"
        #url = "https://registry.hub.docker.com/v2/users/login/"
        
        try:
            r = requests.post(url, data=json.dumps(payload), headers=headers, json=True)
            if r.status_code == 200:
                jsondata = r.json()
                ret = jsondata['token']
            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=("+str(url)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))

        except Exception as err:
            logger.error("could not get token from dockerhub: " + str(err))
            raise err
            
    else:
        # anonymous
        ret = None

    return(ret)

def get_repo_tags_dockerhub_orig(registry, repo, user=None, pw=None):
    ret = {'name':repo, 'tags':[]}

    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        token = get_dockerhub_token_orig(user=user, pw=pw)
        get_manifest_template = "https://registry.hub.docker.com/v2/repositories/{repository}/tags/"
        url = get_manifest_template.format(repository=repo)

        try:
            if token:
                headers = {
                    "Authorization": "JWT " + token
                    #"Authorization": "Bearer {}".format(token),
                    #"Accept": "application/vnd.docker.distribution.manifest.v2+json"
                }
            else:
                headers = {}

            r = requests.get(url, headers=headers,json=True)
            if r.status_code == 200:
                jsondata = r.json()
                for tag in jsondata['results']:
                    if 'name' in tag:
                        ret['tags'].append(tag['name'])
            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=(https://registry.hub.docker.com) repo=("+str(repo)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))

        except Exception as err:
            logger.error("could not get manifest: " + str(err))
            raise err
            
    except Exception as err:
        raise err

    return(ret)

def get_repo_tags_docker_orig(registry, repo, user=None, pw=None):
    ret = {}
    
    try:
        if not user or not pw:
            authy = None
        else:
            authy = (user, pw)

        get_manifest_template = "https://"+registry+"/v2/{repository}/tags/list"
        url = get_manifest_template.format(repository=repo)

        try:
            headers = {}

            r = requests.get(url, headers=headers,json=True, auth=authy, verify=False)
            if r.status_code == 200:
                ret = r.json()
            elif r.status_code == 401:
                raise Exception("not authorized (401) returned from registry: registry=("+str(registry)+") user=("+str(user)+")")
            else:
                raise Exception("got bad code ("+str(r.status_code)+") from manifest request: " + str(r.text))

        except Exception as err:
            logger.error("could not get manifest: " + str(err))
            raise err
            
    except Exception as err:
        raise err

    return(ret)

def get_registry_catalog_orig(userId, registry):
    ret = {}
    user = pw = None
    
    localconfig = anchore_engine.configuration.localconfig.get_config()

    try:
        creds = localconfig['credentials']['users'][userId]['registry_service_auths']['docker'][registry]['auth']
        user,pw = creds.split(":")
    except:
        pass

    if registry == 'docker.io':
        logger.warn("cannot currently get catalog repo list from dockerhub")
    else:
        ret = get_registry_catalog_docker_orig(registry, user=user, pw=pw)

    return(ret)

def get_repo_tags_orig(userId, registry, repo):
    ret = {}
    user = pw = None
    
    localconfig = anchore_engine.configuration.localconfig.get_config()

    try:
        creds = localconfig['credentials']['users'][userId]['registry_service_auths']['docker'][registry]['auth']
        user,pw = creds.split(":")
    except:
        pass

    if registry == 'docker.io':
        if not re.match(".*/.*", repo):
            repo = "library/"+repo
        else:
            repo = repo

        ret = get_repo_tags_dockerhub_orig(registry, repo, user=user, pw=pw)
    else:
        ret = get_repo_tags_docker_orig(registry, repo, user=user, pw=pw)

    return(ret)
