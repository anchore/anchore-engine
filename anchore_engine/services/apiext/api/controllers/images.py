import json
import stat
import datetime
import base64

from flask import request

from anchore_engine.clients import catalog
import anchore_engine.services.common
from anchore_engine.subsys import taskstate, logger
import anchore_engine.configuration.localconfig
import anchore_engine.clients.policy_engine
import anchore_engine.subsys.metrics

from anchore_engine.subsys.metrics import flask_metrics

def make_response_content(content_type, content_data):
    ret = []

    if content_type not in anchore_engine.services.common.image_content_types + anchore_engine.services.common.image_metadata_types:
        logger.warn("input content_type ("+str(content_type)+") not supported ("+str(anchore_engine.services.common.image_content_types)+")")
        return(ret)

    if not content_data:
        logger.warn("empty content data given to format - returning empty result")
        return(ret)

    # type-specific formatting of content data
    if content_type == 'os':
        elkeys = ['license', 'origin', 'size', 'type', 'version']
        for package in content_data.keys():
            el = {}
            try:
                el['package'] = package
                for k in elkeys:
                    if k in content_data[package]:
                        el[k] = content_data[package][k]
                    else:
                        el[k] = None
            except:
                el = {}
            if el:
                ret.append(el)

    elif content_type == 'npm':
        for package in content_data.keys():        
            el = {}
            try:
                el['package'] = content_data[package]['name']
                el['type'] = 'NPM'
                el['location'] = package
                el['version'] = content_data[package]['versions'][0]
                el['origin'] = ','.join(content_data[package]['origins']) or 'Unknown'
                el['license'] = ' '.join(content_data[package]['lics']) or 'Unknown'
            except:
                el = {}
            if el:
                ret.append(el)

    elif content_type == 'gem':
        for package in content_data.keys():
            el = {}
            try:
                el['package'] = content_data[package]['name']
                el['type'] = 'GEM'
                el['location'] = package
                el['version'] = content_data[package]['versions'][0]
                el['origin'] = ','.join(content_data[package]['origins']) or 'Unknown'
                el['license'] = ' '.join(content_data[package]['lics']) or 'Unknown'
            except:
                el = {}
            if el:
                ret.append(el)

    elif content_type == 'python':
        for package in content_data.keys():
            el = {}
            try:
                el['package'] = content_data[package]['name']
                el['type'] = 'PYTHON'
                el['location'] = content_data[package]['location']
                el['version'] = content_data[package]['version']
                el['origin'] = content_data[package]['origin'] or 'Unknown'
                el['license'] = content_data[package]['license'] or 'Unknown'
            except:
                el = {}
            if el:
                ret.append(el)

    elif content_type == 'java':
        for package in content_data.keys():
            el = {}
            try:
                el['package'] = content_data[package]['name']
                el['type'] = content_data[package]['type'].upper()
                el['location'] = content_data[package]['location']
                el['specification-version'] = content_data[package]['specification-version']
                el['implementation-version'] = content_data[package]['implementation-version']
                el['maven-version'] = content_data[package]['maven-version']
                el['origin'] = content_data[package]['origin'] or 'Unknown'
            except:
                el = {}
            if el:
                ret.append(el)

    elif content_type == 'files':
        elmap = {
            'linkdst': 'linkdest',
            'size': 'size',
            'mode': 'mode',
            'sha256': 'sha256',
            'type': 'type',
            'uid': 'uid',
            'gid': 'gid'
        }
        for filename in content_data.keys():
            el = {}
            try:
                el['filename'] = filename
                for elkey in elmap.keys():
                    try:
                        el[elmap[elkey]] = content_data[filename][elkey]
                    except:
                        el[elmap[elkey]] = None

                # special formatting
                el['mode'] = oct(stat.S_IMODE(el['mode']))
                if el['sha256'] == 'DIRECTORY_OR_OTHER':
                    el['sha256'] = None

            except Exception as err:
                el = {}
            if el:
                ret.append(el)        
    elif content_type in ['docker_history']:
        try:
            ret = base64.b64encode(json.dumps(content_data))
        except Exception as err:
            logger.warn("could not convert content to json/base64 encode - exception: {}".format(err))
            ret = ""
    elif content_type in ['manifest', 'dockerfile']:
        try:
            ret = base64.b64encode(content_data)
        except Exception as err:
            logger.warn("could not base64 encode content - exception: {}".format(err))
            ret = ""
    else:
        ret = content_data

    return(ret)

def make_response_vulnerability(vulnerability_type, vulnerability_data):
    ret = []

    if not vulnerability_data:
        logger.warn("empty query data given to format - returning empty result")
        return (ret)

    eltemplate = {
        'vuln': 'None',
        'severity': 'None',
        'url': 'None',
        'fix': 'None',
        'package': 'None',
        'package_name': 'None',
        'package_version': 'None',
        'package_type': 'None',
        'package_cpe': 'None',
        'package_path': 'None',
        'feed': 'None',
        'feed_group': 'None',
    }

    if vulnerability_type == 'os':
        keymap = {
            'vuln': 'CVE_ID',
            'severity': 'Severity',
            'package': 'Vulnerable_Package',
            'fix': 'Fix_Available',
            'url': 'URL',
            'package_type': 'Package_Type',
            'feed': 'Feed',
            'feed_group': 'Feed_Group',
            'package_name': 'Package_Name',
            'package_version': 'Package_Version',
        }
        scan_result = vulnerability_data['legacy_report']
        try:
            for imageId in scan_result.keys():
                header = scan_result[imageId]['result']['header']
                rows = scan_result[imageId]['result']['rows']
                for row in rows:
                    el = {}
                    el.update(eltemplate)
                    for k in keymap.keys():
                        try:
                            el[k] = row[header.index(keymap[k])]
                        except:
                            el[k] = 'None'

                        # conversions
                        if el[k] == 'N/A':
                            el[k] = 'None'

                    ret.append(el)
        except Exception as err:
            logger.warn("could not prepare query response - exception: " + str(err))
            ret = []
    elif vulnerability_type == 'non-os':
        keymap = {
            'vuln': 'vulnerability_id',
            'severity': 'severity',
            'package_name': 'name',
            'package_version': 'version',
            'package_path': 'pkg_path',
            'package_type': 'pkg_type',
            'package_cpe': 'cpe',
            'url': 'link',
            'feed': 'feed_name',
            'feed_group': 'feed_namespace',
        }
        scan_result = vulnerability_data['cpe_report']
        for vuln in scan_result:
            el = {}
            el.update(eltemplate)

            for k in keymap.keys():
                el[k] = vuln[keymap[k]]

            el['package'] = "{}-{}".format(vuln['name'], vuln['version'])

            ret.append(el)
    else:
        ret = vulnerability_data

    return (ret)


def make_response_policyeval(user_auth, eval_record, params):
    ret = {}
    userId, pw = user_auth

    try:
        tag = eval_record['tag']

        ret[tag] = {}

        if eval_record['evalId'] and eval_record['policyId']:
            ret[tag]['detail'] = {}
            if params and 'detail' in params and params['detail']:
                eval_data = catalog.get_document(user_auth, 'policy_evaluations', eval_record['evalId'])
                # ret[tag]['detail']['result'] = json.loads(eval_data)
                ret[tag]['detail']['result'] = eval_data
                bundle_data = catalog.get_document(user_auth, 'policy_bundles', eval_record['policyId'])
                # ret[tag]['detail']['policy'] = json.loads(bundle_data)
                ret[tag]['detail']['policy'] = bundle_data

            ret[tag]['policyId'] = eval_record['policyId']

            if eval_record['final_action'].upper() in ['GO', 'WARN']:
                ret[tag]['status'] = 'pass'
            else:
                ret[tag]['status'] = 'fail'

            ret[tag]['last_evaluation'] = datetime.datetime.utcfromtimestamp(eval_record['created_at']).isoformat() + 'Z'

        else:
            ret[tag]['policyId'] = "N/A"
            ret[tag]['final_action'] = "fail"
            ret[tag]['last_evaluation'] = "N/A"
            ret[tag]['detail'] = {}

    except Exception as err:
        raise Exception("failed to format policy eval response: " + str(err))

    return (ret)


def make_response_image(user_auth, image_record, params={}):
    ret = image_record

    image_content = {'metadata': {}}
    for key in ['arch', 'distro', 'distro_version', 'dockerfile_mode', 'image_size', 'layer_count']:
        val = image_record.pop(key, None)
        image_content['metadata'][key] = val
    image_record['image_content'] = image_content

    if image_record['annotations']:
        try:
            annotation_data = json.loads(image_record['annotations'])
            image_record['annotations'] = annotation_data
        except:
            pass

    # try to assemble full strings
    if image_record and 'image_detail' in image_record:
        for image_detail in image_record['image_detail']:
            try:
                image_detail['fulldigest'] = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail[
                    'digest']
                image_detail['fulltag'] = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail[
                    'tag']
            except:
                image_detail['fulldigest'] = None
                image_detail['fulltag'] = None

            for removekey in ['record_state_val', 'record_state_key']:
                image_detail.pop(removekey, None)

            for datekey in ['last_updated', 'created_at', 'tag_detected_at']:
                try:
                    image_detail[datekey] = datetime.datetime.utcfromtimestamp(image_detail[datekey]).isoformat() + 'Z'
                except:
                    pass

    if params and 'detail' in params and not params['detail']:
        image_record['image_detail'] = []

    for datekey in ['last_updated', 'created_at', 'analyzed_at']:
        try:
            image_record[datekey] = datetime.datetime.utcfromtimestamp(image_record[datekey]).isoformat() +'Z'
        except:
            pass

    for removekey in ['record_state_val', 'record_state_key']:
        image_record.pop(removekey, None)

    return (ret)


def impl_template(request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    try:
        pass
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def lookup_imageDigest_from_imageId(request_inputs, imageId):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    userId, pw = user_auth

    ret = None

    try:
        image_records = catalog.get_image(user_auth, imageId=imageId)
        if image_records:
            image_record = image_records[0]

        imageDigest = image_record['imageDigest']
        ret = imageDigest

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        raise err

    return (ret)

def vulnerability_query(request_inputs, vulnerability_type, doformat=False):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth

    localconfig = anchore_engine.configuration.localconfig.get_config()
    system_user_auth = localconfig['system_user_auth']
    verify = localconfig['internal_ssl_verify']

    force_refresh = params.get('force_refresh', False)
    vendor_only = params.get('vendor_only', True)

    try:
        if vulnerability_type not in anchore_engine.services.common.image_vulnerability_types + ['all']:
            httpcode = 404
            raise Exception("content type ("+str(vulnerability_type)+") not available")

        tag = params.pop('tag', None)
        imageDigest = params.pop('imageDigest', None)
        digest = params.pop('digest', None)

        image_reports = catalog.get_image(user_auth, tag=tag, digest=digest, imageDigest=imageDigest)
        for image_report in image_reports:
            if image_report['analysis_status'] != taskstate.complete_state('analyze'):
                httpcode = 404
                raise Exception("image is not analyzed - analysis_status: " + image_report['analysis_status'])
            imageDigest = image_report['imageDigest']
            try:
                image_detail = image_report['image_detail'][0]
                imageId = image_detail['imageId']
                client = anchore_engine.clients.policy_engine.get_client(user=system_user_auth[0], password=system_user_auth[1], verify_ssl=verify)
                resp = client.get_image_vulnerabilities(user_id=userId, image_id=imageId, force_refresh=force_refresh, vendor_only=vendor_only)
                if doformat:
                    if vulnerability_type == 'all':
                        ret = []
                        for vtype in anchore_engine.services.common.image_vulnerability_types:
                            ret = ret + make_response_vulnerability(vtype, resp.to_dict())
                            #return_object[imageDigest] = make_response_vulnerability(vulnerability_type, resp.to_dict())
                    else:
                        ret = make_response_vulnerability(vulnerability_type, resp.to_dict())
                    return_object[imageDigest] = ret
                else:
                    return_object[imageDigest] = resp.to_dict()

                httpcode = 200
            except Exception as err:
                httpcode = 500
                raise Exception("could not fetch vulnerabilities - exception: " + str(err))

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def get_content(request_inputs, content_type, doformat=False):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth
    try:
        if content_type not in anchore_engine.services.common.image_content_types + anchore_engine.services.common.image_metadata_types:
            httpcode = 404
            raise Exception("content type ("+str(content_type)+") not available")

        tag = params.pop('tag', None)
        imageDigest = params.pop('imageDigest', None)
        digest = params.pop('digest', None)

        image_reports = catalog.get_image(user_auth, tag=tag, digest=digest, imageDigest=imageDigest)
        for image_report in image_reports:
            if image_report['analysis_status'] != taskstate.complete_state('analyze'):
                httpcode = 404
                raise Exception("image is not analyzed - analysis_status: " + image_report['analysis_status'])

            imageDigest = image_report['imageDigest']

            if content_type == 'manifest':
                try:
                    image_manifest_data = catalog.get_document(user_auth, 'manifest_data', imageDigest)
                except Exception as err:
                    raise anchore_engine.services.common.make_anchore_exception(err, input_message="cannot fetch content data {} from archive".format(content_type), input_httpcode=500)

                image_content_data = {
                    'manifest': image_manifest_data
                }
            else:
                try:
                    image_content_data = catalog.get_document(user_auth, 'image_content_data', imageDigest)
                except Exception as err:
                    raise anchore_engine.services.common.make_anchore_exception(err, input_message="cannot fetch content data from archive", input_httpcode=500)

                if content_type not in image_content_data:
                    httpcode = 404
                    raise Exception("image content of type ("+str(content_type)+") was not an available type at analysis time for this image")

            return_object[imageDigest] = make_response_content(content_type, image_content_data[content_type])

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

# repositories C
def add_repository(repository=None, autosubscribe=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'autosubscribe':autosubscribe, 'repository':repository})
        return_object, httpcode = repositories(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

def repositories(request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500

    userId, pw = user_auth

    input_repo = None
    if params and 'repository' in params:
        input_repo = params['repository']

    autosubscribe = False
    if params and 'autosubscribe' in params:
        autosubscribe = params['autosubscribe']

    lookuptag = None
    if params and 'lookuptag' in params:
        lookuptag = params['lookuptag']

    try:
        if method == 'POST':
            logger.debug("handling POST: ")
            try:
                return_object = []
                repo_records = catalog.add_repo(user_auth, regrepo=input_repo, autosubscribe=autosubscribe, lookuptag=lookuptag)
                for repo_record in repo_records:
                    return_object.append(repo_record)
                httpcode = 200
            except Exception as err:
                raise err

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']


    return(return_object, httpcode)

# images CRUD
def list_imagetags():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})

        user_auth = request_inputs['auth']
        method = request_inputs['method']
        bodycontent = request_inputs['bodycontent']
        params = request_inputs['params']

        return_object = {}
        httpcode = 500

        userId, pw = user_auth

        return_object = catalog.get_imagetags(user_auth)
        httpcode = 200
        
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode    


def list_images(history=None, image_to_get=None, fulltag=None):

    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'history': False})
        return_object, httpcode = images(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def add_image(image, force=False):

    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'force': force})
        return_object, httpcode = images(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def delete_image(imageDigest, force=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'force': force})
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image(imageDigest, history=None):
    
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'history': False})
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_by_imageId(imageId, history=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'history': False})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def delete_image_by_imageId(imageId, force=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'force': force})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        return_object, httpcode = images_imageDigest(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_policy_check(imageDigest, policyId=None, tag=None, detail=True, history=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'tag':None, 'detail':True, 'history':False, 'policyId':None})
        return_object, httpcode = images_imageDigest_check(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_policy_check_by_imageId(imageId, policyId=None, tag=None, detail=None, history=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'tag':None, 'detail':True, 'history':False, 'policyId':None})
        return_object, httpcode = images_imageDigest_check(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def list_image_metadata(imageDigest):
    try:
        return_object = anchore_engine.services.common.image_metadata_types
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_metadata_by_type(imageDigest, mtype):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})

        return_object, httpcode = get_content(request_inputs, mtype, doformat=True)
        if httpcode == 200:
            return_object = {
                'imageDigest': imageDigest,
                'metadata_type': mtype,
                'metadata': return_object.values()[0]
            }

    except Exception as err:
        httpcode = 500
        return_object = str(err)
    
    return return_object, httpcode


def list_image_content(imageDigest):
    try:
        return_object = anchore_engine.services.common.image_content_types
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def list_image_content_by_imageid(imageId):
    try:
        return_object = anchore_engine.services.common.image_content_types
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_content_by_type(imageDigest, ctype):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})

        return_object, httpcode = get_content(request_inputs, ctype, doformat=True)
        if httpcode == 200:
            return_object = {
                'imageDigest': imageDigest,
                'content_type': ctype,
                'content': return_object.values()[0]
            }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_content_by_type_imageId(imageId, ctype):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = get_image_content_by_type(imageDigest, ctype)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_vulnerability_types(imageDigest):
    try:
        return_object = anchore_engine.services.common.image_vulnerability_types + ['all']
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_vulnerability_types_by_imageId(imageId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId
            
        return_object, httpcode = get_image_vulnerability_types(imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_vulnerabilities_by_type(imageDigest, vtype, force_refresh=False, vendor_only=True):
    try:
        vulnerability_type = vtype

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest, 'force_refresh': force_refresh, 'vendor_only': vendor_only})
        return_object, httpcode = vulnerability_query(request_inputs, vulnerability_type, doformat=True)
        if httpcode == 200:
            return_object = {
                'imageDigest': imageDigest,
                'vulnerability_type': vulnerability_type,
                'vulnerabilities': return_object.values()[0]
            }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def get_image_vulnerabilities_by_type_imageId(imageId, vtype):
    try:
        vulnerability_type = vtype
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        return_object, httpcode = get_image_vulnerabilities_by_type(imageDigest, vulnerability_type)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
def import_image(analysis_report):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        return_object, httpcode = do_import_image(request_inputs, analysis_report)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def do_import_image(request_inputs, importRequest):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500

    userId, pw = user_auth

    try:
        return_object = []
        image_records = catalog.import_image(user_auth, json.loads(bodycontent))
        for image_record in image_records:
            return_object.append(make_response_image(user_auth, image_record, params))
        httpcode = 200

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return(return_object, httpcode)

def images(request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500

    userId, pw = user_auth
    fulltag = digest = tag = imageId = imageDigest = dockerfile = annotations = None

    history = False
    force = False
    autosubscribe = True
    query_fulltag = None

    if params:
        if 'history' in params:
            history = params['history']

        if 'force' in params:
            force = params['force']

        if 'autosubscribe' in params:
            autosubscribe = params['autosubscribe']

        if 'fulltag' in params:
            query_fulltag = params['fulltag']

    if bodycontent:
        jsondata = json.loads(bodycontent)

        if 'digest' in jsondata:
            digest = jsondata['digest']
        elif 'tag' in jsondata:
            tag = jsondata['tag']
        elif 'imageDigest' in jsondata:
            imageDigest = jsondata['imageDigest']
        elif 'imageId' in jsondata:
            imageId = jsondata['imageId']

        if 'dockerfile' in jsondata:
            dockerfile = jsondata['dockerfile']
        
        if 'annotations' in jsondata:
            annotations = jsondata['annotations']

        autosubscribes = ['analysis_update']
        if autosubscribe:
            autosubscribes.append("tag_update")

    try:
        if method == 'GET':
            logger.debug("handling GET: ")
            try:
                return_object = []

                # Query param fulltag has precedence for search
                if query_fulltag:
                    tag = query_fulltag
                    imageId = imageDigest = digest = None

                image_records = catalog.get_image(user_auth, digest=digest, tag=tag, imageId=imageId,
                                                          imageDigest=imageDigest, history=history)
                for image_record in image_records:
                    return_object.append(make_response_image(user_auth, image_record, params))
                httpcode = 200
            except Exception as err:
                raise err

        elif method == 'POST':
            logger.debug("handling POST: ")
            # if not, add it and set it up to be analyzed
            if not tag:
                # dont support digest add, yet
                httpcode = 500
                raise Exception("digest add unsupported")

            # add the image to the catalog
            image_record = catalog.add_image(user_auth, tag=tag, dockerfile=dockerfile, annotations=annotations)
            imageDigest = image_record['imageDigest']

            # finally, do any state updates and return
            if image_record:
                logger.debug("added image: " + str(imageDigest))

                # auto-subscribe for NOW
                for image_detail in image_record['image_detail']:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']

                    foundtypes = []
                    try:
                        subscription_records = catalog.get_subscription(user_auth, subscription_key=fulltag)
                    except Exception as err:
                        subscription_records = []

                    for subscription_record in subscription_records:
                        if subscription_record['subscription_key'] == fulltag:
                            foundtypes.append(subscription_record['subscription_type'])

                    sub_types = anchore_engine.services.common.subscription_types
                    for sub_type in sub_types:
                        if sub_type in ['repo_update']:
                            continue
                        if sub_type not in foundtypes:
                            try:
                                default_active = False
                                if sub_type in autosubscribes:
                                    logger.debug("auto-subscribing image: " + str(sub_type))
                                    default_active = True
                                catalog.add_subscription(user_auth, {'active': default_active, 'subscription_type': sub_type, 'subscription_key': fulltag})
                            except:
                                try:
                                    catalog.update_subscription(user_auth, {'subscription_type': sub_type, 'subscription_key': fulltag})
                                except:
                                    pass

                # set the state of the image appropriately
                currstate = image_record['analysis_status']
                if not currstate:
                    newstate = taskstate.init_state('analyze', None)
                elif force or currstate == taskstate.fault_state('analyze'):
                    newstate = taskstate.reset_state('analyze')
                elif image_record['image_status'] == 'deleted':
                    newstate = taskstate.reset_state('analyze')
                else:
                    newstate = currstate

                if (currstate != newstate) or (force):
                    logger.debug("state change detected: " + str(currstate) + " : " + str(newstate))
                    image_record.update({'image_status': 'active', 'analysis_status': newstate})
                    updated_image_record = catalog.update_image(user_auth, imageDigest, image_record)
                    if updated_image_record:
                        image_record = updated_image_record[0]
                else:
                    logger.debug("no state change detected: " + str(currstate) + " : " + str(newstate))

                httpcode = 200
                return_object = [make_response_image(user_auth, image_record, params)]
            else:
                httpcode = 500
                raise Exception("failed to add image")

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def images_imageDigest(request_inputs, imageDigest):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500

    userId, pw = user_auth

    try:
        if method == 'GET':
            logger.debug("handling GET on imageDigest: " + str(imageDigest))

            image_records = catalog.get_image(user_auth, imageDigest=imageDigest)
            if image_records:
                return_object = []
                for image_record in image_records:
                    return_object.append(make_response_image(user_auth, image_record, params))
                httpcode = 200
            else:
                httpcode = 404
                raise Exception("cannot locate specified image")

        elif method == 'DELETE':
            logger.debug("handling DELETE on imageDigest: " + str(imageDigest))

            rc = False
            try:
                rc = catalog.delete_image(user_auth, imageDigest, force=params['force'])
            except Exception as err:
                raise err

            if rc:
                return_object = rc
                httpcode = 200
            else:
                httpcode = 500
                raise Exception("failed to delete")

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def images_check_impl(request_inputs, image_records):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = []
    httpcode = 500
    userId, pw = user_auth

    try:
        if 'policyId' in params and params['policyId']:
            bundle_records = catalog.get_policy(user_auth, policyId=params['policyId'])
            policyId = params['policyId']
        else:
            bundle_records = catalog.get_active_policy(user_auth)
            policyId = None
        if not bundle_records:
            httpcode = 404
            raise Exception("user has no active policy to evalute: " + str(user_auth))

        # this is to check that we got at least one evaluation in the response, otherwise routine should throw a 404
        atleastone = False

        if image_records:
            for image_record in image_records:
                imageDigest = image_record['imageDigest']
                return_object_el = {}
                return_object_el[imageDigest] = {}

                tags = []
                if params and 'tag' in params and params['tag']:
                    image_info = anchore_engine.services.common.get_image_info(userId, "docker", params['tag'], registry_lookup=False,
                                                                registry_creds=[])
                    if 'fulltag' in image_info and image_info['fulltag']:
                        params['tag'] = image_info['fulltag']
                    tags.append(params['tag'])

                else:
                    for image_detail in image_record['image_detail']:
                        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                        tags.append(fulltag)

                for tag in tags:
                    if tag not in return_object_el[imageDigest]:
                        return_object_el[imageDigest][tag] = []

                    try:
                        if params and 'history' in params and params['history']:
                            results = catalog.get_evals(user_auth, imageDigest=imageDigest, tag=tag,
                                                               policyId=policyId)
                        else:
                            results = [catalog.get_eval_latest(user_auth, imageDigest=imageDigest, tag=tag,
                                                                       policyId=policyId)]
                    except Exception as err:
                        results = []

                    httpcode = 200
                    for result in results:
                        fresult = make_response_policyeval(user_auth, result, params)
                        return_object_el[imageDigest][tag].append(fresult[tag])
                        atleastone = True

                if return_object_el:
                    return_object.append(return_object_el)
        else:
            httpcode = 404
            raise Exception("could not find image record(s) input imageDigest(s)")

        if not atleastone:
            httpcode = 404
            raise Exception("could not find any evaluations for input images")

    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)


def images_imageDigest_check(request_inputs, imageDigest):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth
    try:
        image_records = catalog.get_image(user_auth, imageDigest=imageDigest)
        for image_record in image_records:
            if image_record['analysis_status'] != taskstate.complete_state('analyze'):
                httpcode = 404
                raise Exception("image is not analyzed - analysis_status: " + str(image_record['analysis_status']))
        return_object, httpcode = images_check_impl(request_inputs, image_records)
    except Exception as err:
        logger.debug("operation exception: " + str(err))
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

