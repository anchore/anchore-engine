import json
import re
import copy
import time
import base64
import hashlib

# anchore modules
import anchore_engine.configuration.localconfig
import anchore_engine.utils

from anchore_engine import db
from anchore_engine.db import db_users
from anchore_engine.subsys import logger
from anchore_engine.clients.policy_engine.generated.models import ImageIngressRequest
from anchore_engine.clients import docker_registry
from anchore_engine.auth import anchore_resources


subscription_types = ['policy_eval', 'tag_update', 'vuln_update', 'repo_update', 'analysis_update']
resource_types = ['registries', 'users', 'images', 'policies', 'evaluations', 'subscriptions', 'archive']
bucket_types = ["analysis_data", "policy_bundles", "policy_evaluations", "query_data", "vulnerability_scan", "image_content_data", "manifest_data"]
super_users = ['admin', 'anchore-system']
image_content_types = ['os', 'files', 'npm', 'gem', 'python', 'java']
image_metadata_types = ['manifest', 'docker_history', 'dockerfile']
image_vulnerability_types = ['os', 'non-os']

def do_simple_pagination(input_items, page=1, limit=None, dosort=True, query_digest="", ttl=0.0):
    page = int(page)
    next_page = None

    if not limit:
        return(1, None, input_items)

    limit = int(limit)
    if dosort:
        input_items.sort()

    start = (page-1)*limit
    end = start + limit
    paginated_items = input_items[start:end]

    if len(paginated_items) == limit and (paginated_items[-1] != input_items[-1]):
        next_page = page + 1

    return(page, next_page, paginated_items)

pagination_cache = {}
def get_cached_pagination(query_digest=""):
    current_time = time.time()

    if query_digest not in pagination_cache:
        raise Exception("document not in pagination cache.")
    elif pagination_cache.get(query_digest, {}).get('ttl', 0.0) < current_time:
        logger.debug("expiring query cache content: {}".format(query_digest))
        el = pagination_cache.pop(query_digest, None)
        del(el)
        raise Exception("document is expired in pagination cache.")

    return(pagination_cache[query_digest]['content'])

def do_cached_pagination(input_items, page=None, limit=None, dosort=True, query_digest="", ttl=0.0):
    current_time = time.time()

    if ttl <= 0.0:
        logger.debug("skipping cache as ttl is <= 0.0 ({})".format(ttl))
    elif query_digest not in pagination_cache:
        logger.debug("caching query content")
        pagination_cache[query_digest] = {
            'ttl': current_time + float(ttl),
            'content': list(input_items),
        }

    return(do_simple_pagination(input_items, page=page, limit=limit, dosort=dosort, query_digest=query_digest, ttl=ttl))

def make_response_paginated_envelope(input_items, envelope_key='result', page="1", limit=None, dosort=True, pagination_func=do_simple_pagination, query_digest="", ttl=0.0):
    page, next_page, paginated_items = pagination_func(input_items, page=page, limit=limit, dosort=dosort, query_digest=query_digest, ttl=ttl)
    return_object = {
        envelope_key: paginated_items,
        'page': "{}".format(page),
        'returned_count': len(paginated_items),
    }
    if next_page:
        return_object['next_page'] = "{}".format(next_page)

    return(return_object)

def update_image_record_with_analysis_data(image_record, image_data):

    image_summary_data = extract_analyzer_content(image_data, 'metadata')

    try:
        image_summary_metadata = copy.deepcopy(image_summary_data)
        if image_summary_metadata:
            logger.debug("getting image summary data")

            summary_record = {}

            adm = image_summary_metadata['anchore_distro_meta']

            summary_record['distro'] = adm.pop('DISTRO', 'N/A')
            summary_record['distro_version'] = adm.pop('DISTROVERS', 'N/A')

            air = image_summary_metadata['anchore_image_report']
            airm = air.pop('meta', {})
            al = air.pop('layers', [])
            ddata = air.pop('docker_data', {})

            summary_record['layer_count'] = str(len(al))
            summary_record['dockerfile_mode'] = air.pop('dockerfile_mode', 'N/A') 
            summary_record['arch'] = ddata.pop('Architecture', 'N/A')            
            summary_record['image_size'] = str(int(airm.pop('sizebytes', 0))) 

            formatted_image_summary_data = summary_record            
    except Exception as err:
        formatted_image_summary_data = {}

    if formatted_image_summary_data:
        image_record.update(formatted_image_summary_data)
        
    dockerfile_content, dockerfile_mode = extract_dockerfile_content(image_data)
    if dockerfile_content and dockerfile_mode:
        image_record['dockerfile_mode'] = dockerfile_mode
        for image_detail in image_record['image_detail']:
            logger.debug("setting image_detail: ")
            image_detail['dockerfile'] = str(base64.b64encode(dockerfile_content.encode('utf-8')), 'utf-8')

    return(True)

if False:
    def format_image_summary(image_summary_data):
        ret = {}

        # augment with image summary data, if available
        try:
            #if not input_image_summary_data:
            #    try:
            #        image_summary_data = catalog.get_document(user_auth, 'image_summary_data', image_record['imageDigest'])
            #    except:
            #        image_summary_data = {}
            #else:
            #    image_summary_data = input_image_summary_data

            #if not image_summary_data:
            #    # (re)generate image_content_data document
            #    logger.debug("generating image summary data from analysis data")
            #    image_data = catalog.get_document(user_auth, 'analysis_data', image_record['imageDigest'])

            #    image_content_data = {}
            #    for content_type in anchore_engine.services.common.image_content_types:
            #        try:
            #            image_content_data[content_type] = anchore_engine.services.common.extract_analyzer_content(image_data, content_type)
            #        except:
            #            image_content_data[content_type] = {}
            #    if image_content_data:
            #        logger.debug("adding image content data to archive")
            #        rc = catalog.put_document(user_auth, 'image_content_data', image_record['imageDigest'], image_content_data)

            #    image_summary_data = {}
            #    try:
            #        image_summary_data = anchore_engine.services.common.extract_analyzer_content(image_data, 'metadata')
            #    except:
            #        image_summary_data = {}

            #    #if image_summary_data:
            #    #    logger.debug("adding image summary data to archive")
            #    #    rc = catalog.put_document(user_auth, 'image_summary_data', image_record['imageDigest'], image_summary_data)

            image_summary_metadata = copy.deepcopy(image_summary_data)
            if image_summary_metadata:
                logger.debug("getting image summary data")

                summary_record = {}

                adm = image_summary_metadata['anchore_distro_meta']

                summary_record['distro'] = adm.pop('DISTRO', 'N/A')
                summary_record['distro_version'] = adm.pop('DISTROVERS', 'N/A')

                air = image_summary_metadata['anchore_image_report']
                airm = air.pop('meta', {})
                al = air.pop('layers', [])
                ddata = air.pop('docker_data', {})

                summary_record['layer_count'] = str(len(al))
                summary_record['dockerfile_mode'] = air.pop('dockerfile_mode', 'N/A') 
                summary_record['arch'] = ddata.pop('Architecture', 'N/A')            
                summary_record['image_size'] = str(int(airm.pop('sizebytes', 0))) 

                ret = summary_record

        except Exception as err:
            logger.warn("cannot format image summary data for image - exception: " + str(err))

        return(ret)


def make_response_error(errmsg, in_httpcode=None, **kwargs):
    if not in_httpcode:
        httpcode = 500
    else:
        httpcode = in_httpcode
    detail = {}
    msg = str(errmsg)

    ret = {
        'message': msg,
        'httpcode': int(httpcode),
        'detail': kwargs.get('detail', {})
    }

    if type(errmsg) == Exception:
        if 'anchore_error_json' in errmsg.__dict__:
            if set(['message', 'httpcode', 'detail']).issubset(set(errmsg.__dict__['anchore_error_json'])):
                ret.update(errmsg.__dict__['anchore_error_json'])
                
    return(ret)

def make_anchore_exception(err, input_message=None, input_httpcode=None, input_detail=None, override_existing=False):
    ret = Exception(err)

    if not input_message:
        message = str(err)
    else:
        message = input_message

    if input_detail != None:
        detail = input_detail
    else:
        detail = {'raw_exception_message': str(err)}

    if not input_httpcode:
        httpcode = 500
    else:
        httpcode = input_httpcode

    anchore_error_json = {}
    try:
        if type(err) == Exception:
            if 'anchore_error_json' in err.__dict__:
                anchore_error_json.update(err.__dict__['anchore_error_json'])
    except:
        pass

    if override_existing or not anchore_error_json:
        ret.anchore_error_json = {
            'message': message,
            'detail': detail,
            'httpcode': httpcode,
        }
    else:
        ret.anchore_error_json = anchore_error_json

    return(ret)

def make_response_routes(apiversion, inroutes):
    return_object = {}
    httpcode = 500

    routes = []
    try:
        for route in inroutes:
            routes.append('/'.join([apiversion, route]))
    except Exception as err:
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    else:
        httpcode = 200
        return_object = routes

    return(return_object, httpcode)

def lookup_registry_image(userId, image_info, registry_creds):
    digest = None
    manifest = None

    if not anchore_resources.registry_access(userId, image_info['registry']):
        raise Exception("access denied for user ("+str(userId)+") registry ("+str(image_info['registry'])+")")
    else:
        try:
            manifest,digest = docker_registry.get_image_manifest(userId, image_info, registry_creds)
            #if 'schemaVersion' not in manifest or manifest['schemaVersion'] != 2:
            #    raise Exception("manifest schemaVersion != 2 not supported")
        except Exception as err:
            raise anchore_engine.services.common.make_anchore_exception(err, input_message="cannot fetch image digest/manifest from registry", input_httpcode=400)
            #raise Exception("cannot fetch image digest/manifest from registry - exception: " + str(err))

    return(digest, manifest)

def get_image_info(userId, image_type, input_string, registry_lookup=False, registry_creds=[]):
    ret = {}
    if image_type == 'docker':
        try:
            image_info = anchore_engine.utils.parse_dockerimage_string(input_string)
        except Exception as err:
            raise anchore_engine.services.common.make_anchore_exception(err, input_message="cannot handle image input string", input_httpcode=400)

        ret.update(image_info)

        if registry_lookup and image_info['registry'] != 'localbuild':
            digest, manifest = lookup_registry_image(userId, image_info, registry_creds)
            image_info['digest'] = digest
            image_info['fulldigest'] = image_info['registry']+"/"+image_info['repo']+"@"+digest
            image_info['manifest'] = manifest
            
            # if we got a manifest, and the image_info does not yet contain an imageId, try to get it from the manifest
            if manifest and not image_info['imageId']:
                try:
                    imageId = re.sub("^sha256:", "", manifest['config']['digest'])
                    image_info['imageId'] = imageId
                except Exception as err:
                    logger.debug("could not extract imageId from fetched manifest - exception: " + str(err))
                    logger.debug("using digest hash as imageId due to incomplete manifest ("+str(image_info['fulldigest'])+")")
                    htype, image_info['imageId'] = image_info['digest'].split(":", 1)

            ret.update(image_info)
        else:
            image_info['manifest'] = {}

    else:
        raise Exception ("image type ("+str(image_type)+") not supported")

    return(ret)

def policy_engine_image_load(client, imageUserId, imageId, imageDigest):

    resp = None

    try:
        request = ImageIngressRequest()
        request.user_id = imageUserId
        request.image_id = imageId
        request.fetch_url='catalog://'+str(imageUserId)+'/analysis_data/'+str(imageDigest)
        logger.debug("policy engine request (image add): " + str(request))
        resp = client.ingress_image(request)
        logger.spew("policy engine response (image add): " + str(resp))
    except Exception as err:
        logger.error("failed to add/check image: " + str(err))
        raise err

    return(resp)

def clean_docker_image_details_for_update(image_details):
    ret = []

    for image_detail in image_details:
        el = {}
        for k in list(image_detail.keys()):
            if image_detail[k] != None:
                el[k] = image_detail[k]
        ret.append(el)
    return(ret)

def make_image_record(userId, image_type, input_string, image_metadata={}, registry_lookup=True, registry_creds=[]):
    if image_type == 'docker':
        try:
            dockerfile = image_metadata['dockerfile']
        except:
            dockerfile = None

        try:
            dockerfile_mode = image_metadata['dockerfile_mode']
        except:
            dockerfile_mode = None

        try:
            tag = image_metadata['tag']
        except:
            tag = None

        try:
            imageId = image_metadata['imageId']
        except:
            imageId = None

        try:
            digest = image_metadata['digest']
        except:
            digest = None

        try:
            annotations = image_metadata['annotations']
        except:
            annotations = {}

        #try:
        #    manifest = image_metadata['manifest']
        #except:
        #    manifest = None

        return(make_docker_image(userId, input_string=input_string, tag=tag, digest=digest, imageId=imageId, dockerfile=dockerfile, dockerfile_mode=dockerfile_mode, registry_lookup=registry_lookup, registry_creds=registry_creds, annotations=annotations))

    else:
        raise Exception("image type ("+str(image_type)+") not supported")

    return(None)

def make_docker_image(userId, input_string=None, tag=None, digest=None, imageId=None, dockerfile=None, dockerfile_mode=None, registry_lookup=True, registry_creds=[], annotations={}):
    ret = {}

    if input_string:
        image_info = get_image_info(userId, "docker", input_string, registry_lookup=registry_lookup, registry_creds=registry_creds)
    else:
        if digest:
            image_info = get_image_info(userId, "docker", digest, registry_lookup=registry_lookup, registry_creds=registry_creds)
            digest = image_info['digest']
            
        if tag:
            image_info = get_image_info(userId, "docker", tag, registry_lookup=registry_lookup, registry_creds=registry_creds)
            if digest and not image_info['digest']:
                image_info['digest'] = digest
        
    if 'digest' in image_info:
        imageDigest = str(image_info['digest'])
    else:
        raise Exception("input image_info needs to have a digest")
        
    if imageId:
        image_info['imageId'] = imageId

    new_input = db.CatalogImage().make()
    new_input['imageDigest'] = imageDigest
    new_input['userId'] = userId
    new_input['image_type'] = 'docker'
    new_input['dockerfile_mode'] = dockerfile_mode

    final_annotation_data = {}
    for k,v in list(annotations.items()):
        if v != 'null':
            final_annotation_data[k] = v
    new_input['annotations'] = json.dumps(final_annotation_data)
    
    new_image_obj = db.CatalogImage(**new_input)
    new_image = dict((key,value) for key, value in vars(new_image_obj).items() if not key.startswith('_'))
    new_image['image_detail'] = []

    if image_info['tag']:
        new_input = db.CatalogImageDocker().make()
        new_input['imageDigest'] = imageDigest
        new_input['userId'] = userId
        new_input['dockerfile'] = dockerfile

        for t in ['registry', 'repo', 'tag', 'digest', 'imageId']:
            if t in image_info:
                new_input[t] = image_info[t]
        
        new_docker_image_obj = db.CatalogImageDocker(**new_input)
        new_docker_image = dict((key,value) for key, value in vars(new_docker_image_obj).items() if not key.startswith('_'))
        new_image['image_detail'] = [new_docker_image]

    ret = new_image
    return(ret)

def make_policy_record(userId, bundle, policy_source="local", active=False):
    payload = {}

    policyId = bundle['id']

    payload["policyId"] = policyId
    payload["active"] = active
    payload["userId"] = userId
    payload['policybundle'] = bundle
    payload['policy_source'] = policy_source

    return(payload)

def make_eval_record(userId, evalId, policyId, imageDigest, tag, final_action, eval_url):
    payload = {}

    payload["policyId"] = policyId
    payload["userId"] = userId
    payload["evalId"] = evalId
    payload["imageDigest"] = imageDigest
    payload["tag"] = tag
    payload["final_action"] = final_action
    payload["policyeval"] = eval_url
    payload["created_at"] = int(time.time())
    payload["last_updated"] = payload['created_at']

    return(payload)

def do_request_prep(request, default_params={}):
    ret = {}
    try:
        try:
            ret['auth'] = (request.authorization.username, request.authorization.password)
        except:
            try:
                ret['auth'] = (request.authorization.username, None)
            except:
                ret['auth'] = (None, None)

        try:
            ret['userId'] = request.authorization.username
        except:
            ret['userId'] = None

        ret['method'] = request.method
        ret['bodycontent'] = str(request.get_data(), 'utf-8') if request.get_data() is not None else None
        ret['params'] = default_params
        for param in list(request.args.keys()):
            if type(request.args[param]) in [str, str]:
                if request.args[param].lower() == 'true':
                    val = True
                elif request.args[param].lower() == 'false':
                    val = False
                else:
                    val = request.args[param]
            else:
                val = request.args[param]

            ret['params'][param] = val

        query_signature = copy.deepcopy(ret)
        query_signature['path'] = request.path
        query_signature.get('params', {}).pop('page', None)
        query_signature.get('params', {}).pop('limit', None)
        ret['pagination_query_digest'] = hashlib.sha256(json.dumps(query_signature, sort_keys=True).encode('utf8')).hexdigest()

    except Exception as err:
        logger.error("error processing request parameters - exception: " + str(err))
        raise err

    return(ret)

def extract_dockerfile_content(image_data):
    dockerfile_content = ""
    dockerfile_mode = "Guessed"

    try:
        dockerfile_content = image_data[0]['image']['imagedata']['image_report']['dockerfile_contents']
        dockerfile_mode = image_data[0]['image']['imagedata']['image_report']['dockerfile_mode']
    except Exception as err:
        dockerfile_content = ""
        dockerfile_mode = "Guessed"

    return(dockerfile_content, dockerfile_mode)

def extract_analyzer_content(image_data, content_type, manifest=None):
    ret = {}
    try:
        idata = image_data[0]['image']
        imageId = idata['imageId']
        
        if content_type == 'files':
            try:
                fcsums = {}
                if 'files.sha256sums' in idata['imagedata']['analysis_report']['file_checksums']:
                    adata = idata['imagedata']['analysis_report']['file_checksums']['files.sha256sums']['base']
                    for k in list(adata.keys()):
                        fcsums[k] = adata[k]

                if 'files.allinfo' in idata['imagedata']['analysis_report']['file_list']:
                    adata = idata['imagedata']['analysis_report']['file_list']['files.allinfo']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        if k in fcsums:
                            avalue['sha256'] = fcsums[k]
                        ret[k] = avalue
                        
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'os':
            try:
                if 'pkgs.allinfo' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.allinfo']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'npm':
            try:
                if 'pkgs.npms' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'gem':
            try:
                if 'pkgs.gems' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'python':
            try:
                if 'pkgs.python' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'java':
            try:
                if 'pkgs.java' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.java']['base']
                    for k in list(adata.keys()):
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'metadata':
            try:
                if 'image_report' in idata['imagedata'] and 'analyzer_meta' in idata['imagedata']['analysis_report']:
                    ret = {'anchore_image_report': image_data[0]['image']['imagedata']['image_report'], 'anchore_distro_meta': image_data[0]['image']['imagedata']['analysis_report']['analyzer_meta']['analyzer_meta']['base']}
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'manifest':
            ret = {}
            try:
                if manifest:
                    ret = json.loads(manifest)
            except:
                ret = {}
        elif content_type == 'docker_history':
            ret = []
            try:
                ret = idata.get('imagedata', {}).get('image_report', {}).get('docker_history', [])
            except:
                ret = []
        elif content_type == 'dockerfile':
            ret = ""
            try:
                if idata.get('imagedata', {}).get('image_report', {}).get('dockerfile_mode', "").lower() == 'actual':
                    ret = idata.get('imagedata', {}).get('image_report', {}).get('dockerfile_contents', "")
            except:
                ret = ""

    except Exception as err:
        logger.warn("exception: " + str(err))
        raise err

    return(ret)


def get_system_user_auth(session=None):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if 'system_user_auth' in localconfig and localconfig['system_user_auth'] != (None, None):
        return(localconfig['system_user_auth'])

    if session:
        system_user = db_users.get('anchore-system', session=session)
        if system_user:
            return( (system_user['userId'], system_user['password']) )

    return ( (None, None) )
