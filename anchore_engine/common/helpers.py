"""
Common message types and marshalling helper functions
"""
import base64
import copy
import json
import time

from anchore_engine.subsys import logger


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