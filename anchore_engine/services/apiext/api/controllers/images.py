import datetime
import json

from flask import request

from anchore_engine.clients import catalog
import anchore_engine.services.common
from anchore_engine.subsys import taskstate, logger
import anchore_engine.configuration.localconfig
import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport


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


def make_response_image(image_record, params={}):
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

def vulnerability_query(request_inputs, queryType, doformat=False):
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
                if not queryType:
                    raise Exception("queryType must be set")
                elif queryType == 'cve-scan':
                    image_detail = image_report['image_detail'][0]
                    imageId = image_detail['imageId']
                    client = anchore_engine.clients.policy_engine.get_client(user=system_user_auth[0], password=system_user_auth[1], verify_ssl=verify)
                    resp = client.get_image_vulnerabilities(user_id=userId, image_id=imageId, force_refresh=False)
                    if doformat:
                        return_object[imageDigest] = make_response_query(queryType, resp.to_dict())
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
            # query_data = json.loads(catalog.get_document(user_auth, 'query_data', imageDigest))
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
        return_object = ['os', 'npm', 'gem', 'files']
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def list_image_content_by_imageid(imageId):
    try:
        return_object = ['os', 'npm', 'gem', 'files']
        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_content_by_type(imageDigest, ctype):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})

        if ctype == 'os':
            queryType = "list-package-detail"
        elif ctype == 'npm':
            queryType = "list-npm-detail"
        elif ctype == 'gem':
            queryType = "list-gem-detail"
        elif ctype == 'files':
            queryType = "list-files-detail"
        else:
            queryType = ctype

        return_object, httpcode = query(request_inputs, queryType, doformat=True)

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

        if ctype == 'os':
            queryType = "list-package-detail"
        elif ctype == 'npm':
            queryType = "list-npm-detail"
        elif ctype == 'gem':
            queryType = "list-gem-detail"
        elif ctype == 'files':
            queryType = "list-files-detail"
        else:
            queryType = ctype

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})
        return_object, httpcode = query(request_inputs, queryType, doformat=True)

        return_object = {
            'imageDigest': imageDigest,
            'content_type': ctype,
            'content': return_object.values()[0]
        }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_vulnerability_types(imageDigest):
    try:
        return_object = ['os']
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_vulnerability_types_by_imageId(imageId):
    try:
        return_object = ['os']
        httpcode = 200

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_vulnerabilities_by_type(imageDigest, vtype):
    try:
        if vtype == 'os':
            queryType = "cve-scan"
        else:
            queryType = vtype

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})

        #return_object, httpcode = query(request_inputs, queryType, doformat=True)
        return_object, httpcode = vulnerability_query(request_inputs, queryType, doformat=True)

        return_object = {
            'imageDigest': imageDigest,
            'vulnerability_type': vtype,
            'vulnerabilities': return_object.values()[0]
        }


    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def get_image_vulnerabilities_by_type_imageId(imageId, vtype):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        try:
            imageDigest = lookup_imageDigest_from_imageId(request_inputs, imageId)
        except:
            imageDigest = imageId

        if vtype == 'os':
            queryType = "cve-scan"
        else:
            queryType = vtype

        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={'imageDigest':imageDigest})
        #return_object, httpcode = query(request_inputs, queryType, doformat=True)
        return_object, httpcode = vulnerability_query(request_inputs, queryType, doformat=True)

        return_object = {
             'imageDigest': imageDigest,
             'vulnerability_type': vtype,
             'vulnerabilities': return_object.values()[0]
        }

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


def import_image(importRequest):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(request, default_params={})
        return_object, httpcode = do_import_image(request_inputs, importRequest)

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
            return_object.append(make_response_image(image_record, params))
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
                    return_object.append(make_response_image(image_record, params))
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
                elif force:
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
                    return_object.append(make_response_image(image_record, params))

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
                    return_object.append(make_response_image(image_record, params))
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
