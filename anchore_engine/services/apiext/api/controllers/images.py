import json
import copy
import stat
import time
import datetime

from flask import request

from anchore_engine.clients import catalog
import anchore_engine.services.common
from anchore_engine.subsys import taskstate, logger
import anchore_engine.configuration.localconfig
import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

def get_image_summary(user_auth, image_record):
    ret = {}
    if image_record['analysis_status'] != taskstate.complete_state('analyze'):
        return(ret)

    # augment with image summary data, if available
    try:
        try:
            image_summary_data = catalog.get_document(user_auth, 'image_summary_data', image_record['imageDigest'])
        except:
            image_summary_data = {}

        if not image_summary_data:
            # (re)generate image_content_data document
            logger.debug("generating image summary data from analysis data")
            image_data = catalog.get_document(user_auth, 'analysis_data', image_record['imageDigest'])

            image_content_data = {}
            for content_type in anchore_engine.services.common.image_content_types:
                try:
                    image_content_data[content_type] = anchore_engine.services.common.extract_analyzer_content(image_data, content_type)
                except:
                    image_content_data[content_type] = {}
            if image_content_data:
                logger.debug("adding image content data to archive")
                rc = catalog.put_document(user_auth, 'image_content_data', image_record['imageDigest'], image_content_data)

            image_summary_data = {}
            try:
                image_summary_data = anchore_engine.services.common.extract_analyzer_content(image_data, 'metadata')
            except:
                image_summary_data = {}
            if image_summary_data:
                logger.debug("adding image summary data to archive")
                rc = catalog.put_document(user_auth, 'image_summary_data', image_record['imageDigest'], image_summary_data)

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
        logger.warn("cannot get image summary data for image: " + str(image_record['imageDigest']) + " : " + str(err))

    return(ret)

def make_response_content(content_type, content_data):
    ret = []

    if content_type not in anchore_engine.services.common.image_content_types:
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
                        #el.pop(elmap[elkey], None)
                        el[elmap[elkey]] = None

                # special formatting
                el['mode'] = oct(stat.S_IMODE(el['mode']))
                if el['sha256'] == 'DIRECTORY_OR_OTHER':
                    el['sha256'] = None

                #el['mode'] = oct(stat.S_IMODE(content_data[filename]['mode']))
                #el['linkdest'] = content_data[filename]['linkdst']
                #el['sha256'] = content_data[filename]['sha256']
                #el['size'] = content_data[filename]['size']
                #el['type'] = content_data[filename]['type']
                #el['uid'] = content_data[filesname]['uid']
                #el['gid'] = content_data[filesname]['gid']

            except Exception as err:
                el = {}
            if el:
                ret.append(el)        
    else:
        ret = content_data

    return(ret)

def make_response_vulnerability(vulnerability_type, vulnerability_data):
    ret = []

    if not vulnerability_data:
        logger.warn("empty query data given to format - returning empty result")
        return (ret)

    if vulnerability_type == 'os':
        keymap = {
            'vuln': 'CVE_ID',
            'severity': 'Severity',
            'package': 'Vulnerable_Package',
            'fix': 'Fix_Available',
            'url': 'URL'
        }
        scan_result = vulnerability_data['legacy_report']
        try:
            for imageId in scan_result.keys():
                header = scan_result[imageId]['result']['header']
                rows = scan_result[imageId]['result']['rows']
                for row in rows:
                    el = {}
                    for k in keymap.keys():
                        try:
                            el[k] = row[header.index(keymap[k])]
                        except:
                            el[k] = None

                        # conversions
                        if el[k] == 'N/A':
                            el[k] = None

                    ret.append(el)
        except Exception as err:
            logger.warn("could not prepare query response - exception: " + str(err))
            ret = []
    else:
        ret = vulnerability_data

    return (ret)

def make_response_query(queryType, query_data):
    ret = []

    if not query_data:
        logger.warn("empty query data given to format - returning empty result")
        return (ret)

    if queryType == 'cve-scan':
        keymap = {
            'vuln': 'CVE_ID',
            'severity': 'Severity',
            'package': 'Vulnerable_Package',
            'fix': 'Fix_Available',
            'url': 'URL'
        }
        scan_result = query_data['legacy_report']
        try:
            for imageId in scan_result.keys():
                header = scan_result[imageId]['result']['header']
                rows = scan_result[imageId]['result']['rows']
                for row in rows:
                    el = {}
                    for k in keymap.keys():
                        try:
                            el[k] = row[header.index(keymap[k])]
                        except:
                            el[k] = None

                        # conversions
                        if el[k] == 'N/A':
                            el[k] = None

                    ret.append(el)
        except Exception as err:
            logger.warn("could not prepare query response - exception: " + str(err))
            ret = []

    elif queryType in ['list-package-detail', 'list-npm-detail', 'list-gem-detail']:
        keymap = {
            'package': 'Package_Name',
            'type': 'Type',
            'size': 'Size',
            'version': 'Version',
            'origin': 'Origin',
            'license': 'License',
            'location': 'Location'
        }

        try:
            for imageId in query_data.keys():
                header = query_data[imageId]['result']['header']
                rows = query_data[imageId]['result']['rows']
                for row in rows:
                    el = {}
                    for k in keymap.keys():
                        try:
                            el[k] = row[header.index(keymap[k])]
                        except:
                            el[k] = None

                        # conversions
                        if el[k] == 'N/A':
                            el[k] = None
                        elif k == 'size':
                            try:
                                el[k] = int(el[k])
                            except:
                                el[k] = None
                        elif k == 'type' and not el[k]:
                            if queryType == 'list-npm-detail':
                                el[k] = 'NPM'
                            elif queryType == 'list-gem-detail':
                                el[k] = 'GEM'
                    if queryType == 'list-package-detail' and 'location' in el:
                        el.pop('location', None)
                    ret.append(el)
        except Exception as err:
            logger.warn("could not prepare query response - exception: " + str(err))
            ret = []

    elif queryType == 'list-files-detail':
        keymap = {
            'filename': 'Filename',
            'type': 'Type',
            'size': 'Size',
            'mode': 'Mode',
            'sha256': 'Checksum',
            'linkdest': 'Link_Dest'
        }

        try:
            for imageId in query_data.keys():
                header = query_data[imageId]['result']['header']
                rows = query_data[imageId]['result']['rows']
                for row in rows:
                    el = {}
                    for k in keymap.keys():
                        try:
                            el[k] = row[header.index(keymap[k])]
                        except:
                            el[k] = None

                        # conversions
                        if el[k] == 'N/A':
                            el[k] = None
                        elif el[k] == 'DIRECTORY_OR_OTHER':
                            el[k] = None
                        elif k == 'size':
                            el[k] = int(el[k])

                    ret.append(el)
        except Exception as err:
            logger.warn("could not prepare query response - exception: " + str(err))
            ret = []
    else:
        ret = query_data

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

            ret[tag]['last_evaluation'] = datetime.datetime.fromtimestamp(eval_record['created_at']).isoformat()

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

            for datekey in ['last_updated', 'created_at']:
                try:
                    image_detail[datekey] = datetime.datetime.utcfromtimestamp(image_detail[datekey]).isoformat()
                except:
                    pass

    if params and 'detail' in params and not params['detail']:
        image_record['image_detail'] = []

    for datekey in ['last_updated', 'created_at']:
        try:
            image_record[datekey] = datetime.datetime.utcfromtimestamp(image_record[datekey]).isoformat()
        except:
            pass


    image_content_metadata = {}
    try:
        image_content_metadata = get_image_summary(user_auth, image_record)
    except:
        image_content_metadata = {}

    ret['image_content'] = {}
    ret['image_content']['metadata'] = image_content_metadata

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

    try:
        if vulnerability_type not in anchore_engine.services.common.image_vulnerability_types:
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
                if vulnerability_type == 'os':
                    image_detail = image_report['image_detail'][0]
                    imageId = image_detail['imageId']
                    client = anchore_engine.clients.policy_engine.get_client(user=system_user_auth[0], password=system_user_auth[1], verify_ssl=verify)
                    resp = client.get_image_vulnerabilities(user_id=userId, image_id=imageId, force_refresh=False)
                    if doformat:
                        return_object[imageDigest] = make_response_vulnerability(vulnerability_type, resp.to_dict())
                    else:
                        return_object[imageDigest] = resp.to_dict()
                else:
                    return_object[imageDigest] = []

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
        if content_type not in anchore_engine.services.common.image_content_types:
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
            image_content_data = catalog.get_document(user_auth, 'image_content_data', imageDigest)
            return_object[imageDigest] = make_response_content(content_type, image_content_data[content_type])

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

def query(request_inputs, queryType, doformat=False):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    bodycontent = request_inputs['bodycontent']
    params = request_inputs['params']

    return_object = {}
    httpcode = 500
    userId, pw = user_auth
    try:
        tag = params.pop('tag', None)
        imageDigest = params.pop('imageDigest', None)
        digest = params.pop('digest', None)

        image_reports = catalog.get_image(user_auth, tag=tag, digest=digest, imageDigest=imageDigest)
        for image_report in image_reports:
            if image_report['analysis_status'] != taskstate.complete_state('analyze'):
                httpcode = 404
                raise Exception("image is not analyzed - analysis_status: " + image_report['analysis_status'])
            imageDigest = image_report['imageDigest']
            query_data = catalog.get_document(user_auth, 'query_data', imageDigest)
            if not queryType:
                return_object[imageDigest] = query_data.keys()
            elif queryType in query_data:
                if doformat:
                    return_object[imageDigest] = make_response_query(queryType, query_data[queryType])
                else:
                    return_object[imageDigest] = query_data[queryType]

            else:
                return_object[imageDigest] = []

        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    return (return_object, httpcode)

# images CRUD
def list_images(history=None, image_to_get=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'history': False})
        return_object, httpcode = images(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def add_image(image, force=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'force': False})
        return_object, httpcode = images(request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def delete_image(imageDigest):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
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


def delete_image_by_imageId(imageId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
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


def get_image_policy_check(imageDigest, policyId=None, tag=None, detail=None, history=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'tag':None, 'detail':True, 'history':False, 'policyId':None})
        return_object, httpcode = images_imageDigest_check(request_inputs, imageDigest)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


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


def list_image_content(imageDigest):
    try:
        return_object = anchore_engine.services.common.image_content_types
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def list_image_content_by_imageid(imageId):
    try:
        return_object = anchore_engine.services.common.image_content_types
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

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


def get_image_vulnerability_types(imageDigest):
    try:
        return_object = anchore_engine.services.common.image_vulnerability_types
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


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


def get_image_vulnerabilities_by_type(imageDigest, vtype):
    try:
        vulnerability_type = vtype
        #if vtype == 'os':
        #    vulnerability_type = "cve-scan"
        #else:
        #    vulnerability_type = vtype

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})
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
            #try:
            #    image_content_metadata = get_image_summary(user_auth, image_record)
            #except:
            #    image_content_metadata = {}
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
    digest = tag = imageId = imageDigest = dockerfile = None

    history = False
    if params and 'history' in params:
        history = params['history']

    force = False
    if params and 'force' in params:
        force = params['force']

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

    try:
        if method == 'GET':
            logger.debug("handling GET: ")
            try:
                return_object = []
                image_records = catalog.get_image(user_auth, digest=digest, tag=tag, imageId=imageId,
                                                          imageDigest=imageDigest, history=history)
                for image_record in image_records:
                    #try:
                    #    image_content_metadata = get_image_summary(user_auth, image_record)
                    #except:
                    #    image_content_metadata = {}
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
            else:
                # add the image to the catalog
                image_record = catalog.add_image(user_auth, tag=tag, dockerfile=dockerfile)
                imageDigest = image_record['imageDigest']

            # finally, do any state updates and return
            if image_record:
                logger.debug("fetched image_info: " + json.dumps(image_record, indent=4))

                # auto-subscribe for NOW
                for image_detail in image_record['image_detail']:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']

                    foundtypes = []
                    try:
                        subscription_records = catalog.get_subscription(user_auth)
                        for subscription_record in subscription_records:
                            if subscription_record['subscription_key'] == fulltag:
                                foundtypes.append(subscription_record['subscription_type'])
                    except Exception as err:
                        logger.warn("cannot load subscription records - exception: " + str(err))
                    
                    sub_types = anchore_engine.services.common.subscription_types
                    for sub_type in sub_types:
                        if sub_type not in foundtypes:
                            try:
                                default_active = False
                                if sub_type in ['tag_update']:
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
                    rc = catalog.update_image(user_auth, imageDigest, image_record)
                else:
                    logger.debug("no state change detected: " + str(currstate) + " : " + str(newstate))

                httpcode = 200
                image_records = catalog.get_image(user_auth, digest=digest, tag=tag, registry_lookup=False)

                return_object = []
                for image_record in image_records:
                    #try:
                    #    image_content_metadata = get_image_summary(user_auth, image_record)
                    #except:
                    #    image_content_metadata = {}
                    return_object.append(make_response_image(user_auth, image_record, params))

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
                    #try:
                    #    query_data = catalog.get_document(user_auth, 'query_data', imageDigest)
                    #    if 'anchore_image_summary' in query_data and query_data['anchore_image_summary']:
                    #        logger.debug("getting image summary data")
                    #except Exception as err:
                    #    logger.warn("cannot get image summary data for image: " + str(imageDigest))
                    #try:
                    #    image_content_metadata = get_image_summary(user_auth, image_record)
                    #except:
                    #    image_content_metadata = {}
                    return_object.append(make_response_image(user_auth, image_record, params))
                httpcode = 200
            else:
                httpcode = 404
                raise Exception("cannot locate specified image")

        elif method == 'DELETE':
            logger.debug("handling DELETE on imageDigest: " + str(imageDigest))

            rc = False
            try:
                rc = catalog.delete_image(user_auth, imageDigest)
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
                            results = catalog.get_eval(user_auth, imageDigest=imageDigest, tag=tag,
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
