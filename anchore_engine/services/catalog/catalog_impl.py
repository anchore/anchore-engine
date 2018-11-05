import json
import hashlib
import time
import base64

from dateutil import parser as dateparser

import anchore_engine.apis.authorization
import anchore_engine.common
import anchore_engine.configuration.localconfig
import anchore_engine.common.helpers
import anchore_engine.common.images
from anchore_engine.auth import aws_ecr
import anchore_engine.services.catalog
import anchore_engine.utils

from anchore_engine import utils as anchore_utils
from anchore_engine.subsys import taskstate, logger, archive as archive_sys, notifications
import anchore_engine.subsys.metrics
from anchore_engine.clients import docker_registry
from anchore_engine.db import db_subscriptions, db_catalog_image, db_policybundle, db_policyeval, db_events,\
    db_registries, db_services, db_archivedocument, db_accounts
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.subsys.identities import manager_factory

def policy_engine_image_load(client, imageUserId, imageId, imageDigest):
    """
    Helper function for constructing the call to the PE for loading images

    :param client:
    :param imageUserId:
    :param imageId:
    :param imageDigest:
    :return:
    """
    try:
        fetch_url='catalog://{user_id}/analysis_data/{digest}'.format(user_id=imageUserId, digest=imageDigest)

        logger.debug("policy engine request (image add): img_user_id={}, image_id={}, fetch_url={}".format(imageUserId, imageId, fetch_url))
        resp = client.ingress_image(user_id=imageUserId, image_id=imageId, analysis_fetch_url=fetch_url)
        logger.spew("policy engine response (image add): " + str(resp))
    except Exception as err:
        logger.error("failed to add/check image: " + str(err))
        raise err

    return(resp)

def registry_lookup(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None

    try:
        for t in ['tag', 'digest']:
            if t in params:
                input_string = params[t]
                if input_string:
                    input_type = t
                    image_info = anchore_engine.common.images.get_image_info(userId, "docker", input_string, registry_lookup=False, registry_creds=(None, None))
                    break

        if not image_info:
            httpcode = 500
            raise Exception("need 'tag' or 'digest' in url params")
        else:
            try:
                registry_creds = db_registries.get_byuserId(userId, session=dbsession)
                try:
                    refresh_registry_creds(registry_creds, dbsession)
                except Exception as err:
                    logger.warn("failed to refresh registry credentials - exception: " + str(err))

                digest, manifest = anchore_engine.common.images.lookup_registry_image(userId, image_info, registry_creds)
                return_object['digest'] = image_info['registry'] + "/" + image_info['repo'] + "@" + digest
                return_object['manifest'] = manifest
                httpcode = 200
            except Exception as err:
                httpcode = 404
                raise Exception("cannot lookup image in registry - detail: " + str(err))
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def repo(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    fulltag = None
    regrepo = False
    if params and 'regrepo' in params:
        regrepo = params['regrepo']

    autosubscribe = False
    if params and 'autosubscribe' in params:
        autosubscribe = params['autosubscribe']

    lookuptag = 'latest'
    if params and 'lookuptag' in params and params['lookuptag']:
        lookuptag = str(params['lookuptag'])

    fulltag = regrepo + ":" + lookuptag

    try:
        if method == 'POST':
            image_info = anchore_engine.common.images.get_image_info(userId, "docker", fulltag, registry_lookup=False, registry_creds=(None, None))

            registry_creds = db_registries.get_byuserId(userId, session=dbsession)
            try:
                refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

            repotags = []
            try:
                repotags = docker_registry.get_repo_tags(userId, image_info, registry_creds=registry_creds)
            except Exception as err:
                httpcode = 404
                logger.warn("no tags could be added from input regrepo ("+str(regrepo)+") - exception: " + str(err))
                raise Exception("no tags could be added from input regrepo ("+str(regrepo)+")")

            try:
                regrepo = image_info['registry']+"/"+image_info['repo']

                dbfilter = {
                    'subscription_type': 'repo_update',
                    'subscription_key': regrepo
                }
                
                subscription_records = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
                if not subscription_records:
                    rc = db_subscriptions.add(userId, regrepo, 'repo_update', {'active': True, 'subscription_value': json.dumps({'autosubscribe': autosubscribe, 'lookuptag': lookuptag, 'tagcount': len(repotags)})}, session=dbsession)
                    if not rc:
                        raise Exception ("adding required subscription failed")

                else:
                    # update new metadata
                    subscription_record = subscription_records[0]
                    subscription_value = json.loads(subscription_record['subscription_value'])
                    subscription_value['autosubscribe'] = autosubscribe
                    subscription_value['lookuptag'] = lookuptag
                    rc = db_subscriptions.update(userId, regrepo, 'repo_update', {'subscription_value': json.dumps(subscription_value)}, session=dbsession)

                subscription_records = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            except Exception as err:
                httpcode = 500
                raise Exception("could not add the required subscription to anchore-engine")
                
            if not subscription_records:
                httpcode = 500
                raise Exception("unable to add/update subscripotion records in anchore-engine")

            return_object = subscription_records
            return_object[0]['subscription_value'] = json.dumps({'autosubscribe': autosubscribe, 'repotags': repotags, 'tagcount': len(repotags), 'lookuptag': lookuptag})

            httpcode = 200
            
            # check and kick a repo watcher task if necessary
            try:
                rc = anchore_engine.services.catalog.schedule_watcher("repo_watcher")
                logger.debug("scheduled repo_watcher task")
            except Exception as err:
                logger.warn("failed to schedule repo_watcher task: " + str(err))
                pass

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def image_tags(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        if method == 'GET':
            httpcode = 200
            return_object = db_catalog_image.get_all_tagsummary(userId, session=dbsession)
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def image(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None

    # set up params
    registry_lookup = False
    if params and 'registry_lookup' in params:
        registry_lookup = params['registry_lookup']

    history = False
    if params and 'history' in params:
        history = params['history']

    httpcode = 500
    try:
        for t in ['tag', 'digest', 'imageId']:
            if t in params:
                input_string = params[t]
                if input_string:
                    input_type = t
                    image_info = anchore_engine.common.images.get_image_info(userId, "docker", input_string, registry_lookup=False, registry_creds=(None, None))
                    break

        if method == 'GET':
            if not input_string:
                httpcode = 200
                return_object = db_catalog_image.get_all_byuserId(userId, session=dbsession)
            else:
                if registry_lookup:
                    try:
                        registry_creds = db_registries.get_byuserId(userId, session=dbsession)
                        try:
                            refresh_registry_creds(registry_creds, dbsession)
                        except Exception as err:
                            logger.warn("failed to refresh registry credentials - exception: " + str(err))
                        image_info = anchore_engine.common.images.get_image_info(userId, "docker", input_string, registry_lookup=True, registry_creds=registry_creds)
                    except Exception as err:
                        httpcode = 404
                        raise Exception("cannot perform registry lookup - exception: " + str(err))

                if image_info:
                    try:
                        if history:
                            if input_type == 'tag':
                                filterkeys = ['registry', 'repo', 'tag', 'imageId']
                            else:
                                raise Exception("cannot use history without specifying an input tag")
                        else:
                            filterkeys = ['registry', 'repo', 'tag', 'digest', 'imageId']

                        dbfilter = {}
                        for k in filterkeys:
                            if k in image_info and image_info[k]:
                                dbfilter[k] = image_info[k]

                        logger.debug("image DB lookup filter: " + json.dumps(dbfilter, indent=4))
                        if history:
                            image_records = db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter=dbfilter, session=dbsession)
                        else:
                            image_records = db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter=dbfilter, onlylatest=True, session=dbsession)

                        if image_records:
                            return_object = image_records
                            httpcode = 200
                        else:
                            httpcode = 404
                            raise Exception("image data not found in DB")
                    except Exception as err:
                        raise err
                else:
                    httpcode = 404
                    raise Exception("image not found in DB")

        elif method == 'POST':
            timer = time.time()

            logger.debug("MARK0: " + str(time.time() - timer))
            if input_type == 'digest':
                raise Exception("catalog add requires a tag string to determine registry/repo")

            # body
            jsondata = {}
            if bodycontent:
                jsondata = bodycontent
    
            dockerfile = None
            dockerfile_mode = None
            if 'dockerfile' in jsondata:
                dockerfile = jsondata['dockerfile']
                try:
                    # this is a check to ensure the input is b64 encoded
                    base64.decodebytes(dockerfile.encode('utf-8'))
                    dockerfile_mode = "Actual"
                except Exception as err:
                    raise Exception("input dockerfile data must be base64 encoded - exception on decode: " + str(err))

            annotations = {}
            if 'annotations' in jsondata:
                annotations = jsondata['annotations']

            logger.debug("MARK1: " + str(time.time() - timer))

            image_record = {}
            try:
                registry_creds = db_registries.get_byuserId(userId, session=dbsession)
                try:
                    refresh_registry_creds(registry_creds, dbsession)
                except Exception as err:
                    logger.warn("failed to refresh registry credentials - exception: " + str(err))

                logger.debug("MARK2: " + str(time.time() - timer))

                image_info_overrides = {}

                input_tag = params.get('tag', None)
                input_digest = params.get('digest', None)
                if input_tag and input_digest:
                    input_fulldigest = "{}/{}@{}".format(image_info['registry'], image_info['repo'], input_digest)
                    image_info_overrides['fulltag'] = input_tag
                    image_info_overrides['tag'] = image_info['tag']
                    if params.get('created_at', None):
                        image_info_overrides['created_at_override'] = params.get('created_at')

                    input_string = input_fulldigest

                input_strings = [input_string]

                for input_string in input_strings:
                    logger.debug("INPUT STRING: {}".format(input_string))
                    logger.debug("INPUT IMAGE INFO: {}".format(image_info))
                    logger.debug("INPUT IMAGE INFO OVERRIDES: {}".format(image_info_overrides))
                    image_info = anchore_engine.common.images.get_image_info(userId, 'docker', input_string, registry_lookup=True, registry_creds=registry_creds)

                    if image_info_overrides:
                        image_info.update(image_info_overrides)

                    logger.debug("INPUT FINAL IMAGE INFO: {}".format(image_info))
                    logger.debug("MARK3: " + str(time.time() - timer))

                    manifest = None
                    try:
                        if 'manifest' in image_info:
                            manifest = json.dumps(image_info['manifest'])
                        else:
                            raise Exception("no manifest from get_image_info")
                    except Exception as err:
                        raise Exception("could not fetch/parse manifest - exception: " + str(err))

                    logger.debug("MARK4: " + str(time.time() - timer))

                    logger.debug("ADDING/UPDATING IMAGE IN IMAGE POST: " + str(image_info))
                    image_records = add_or_update_image(dbsession, userId, image_info['imageId'], tags=[image_info['fulltag']], digests=[image_info['fulldigest']], parentdigest=image_info.get('parentdigest', None), created_at=image_info.get('created_at_override', None), dockerfile=dockerfile, dockerfile_mode=dockerfile_mode, manifest=manifest, annotations=annotations)
                    logger.debug("MARK5: " + str(time.time() - timer))
                    if image_records:
                        image_record = image_records[0]

            except Exception as err:
                logger.exception('Error adding image')
                httpcode = 404
                raise err

            if image_record:
                httpcode = 200
                return_object = image_record
            else:
                httpcode = 404
                raise Exception("could not add input image")

    except Exception as err:
        logger.exception('Error processing image request')
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def image_imageDigest(dbsession, request_inputs, imageDigest, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None
    
    try:
        if method == 'GET':
            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
            if image_record:
                httpcode = 200
                return_object = [image_record]
            else:
                httpcode = 404
                raise Exception("image not found in DB")

        elif method == 'DELETE':
            try:
                image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
                if image_record:
                    
                    return_object, httpcode = do_image_delete(userId, image_record, dbsession, force=params['force'])
                    if httpcode not in list(range(200,299)):
                        raise Exception(return_object)

                else:
                    return_object = True
                    httpcode = 200

            except Exception as err:
                #httpcode = 500
                raise err
            
        elif method == 'PUT':
            # update an image

            jsondata = {}
            if bodycontent:
                jsondata = bodycontent

            updated_image_record = jsondata

            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
            if image_record:
                rc = db_catalog_image.update_record(updated_image_record, session=dbsession)
                image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)

                httpcode = 200
                return_object = [image_record]
            else:
                httpcode = 404
                raise Exception("image not found")

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def image_import(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        jsondata = {}
        if bodycontent:
            try:
                jsondata = bodycontent
            except Exception as err:
                raise err

        anchore_data = [jsondata]

        try:
            # extract necessary input from anchore analysis data
            a = anchore_data[0]
            imageId = a['image']['imageId']
            docker_data = a['image']['imagedata']['image_report']['docker_data']

            digests = []
            islocal = False
            if not docker_data['RepoDigests']:
                islocal = True
            else:
                for digest in docker_data['RepoDigests']:
                    digests.append(digest)

            tags = []
            for tag in docker_data['RepoTags']:
                image_info = anchore_engine.utils.parse_dockerimage_string(tag)
                if islocal:
                    image_info['registry'] = 'localbuild'
                    digests.append(image_info['registry'] + "/" + image_info['repo'] + "@local:" + imageId)
                fulltag = image_info['registry'] + "/" + image_info['repo'] + ":" + image_info['tag']
                tags.append(fulltag)
                
            # add the image w input anchore_analysis, as already analyzed
            logger.debug("ADDING/UPDATING IMAGE IN IMAGE IMPORT: " + str(imageId))
            ret_list = add_or_update_image(dbsession, userId, imageId, tags=tags, digests=digests, anchore_data=anchore_data)

            client = internal_client_for(PolicyEngineClient, userId)
            for image_report in ret_list:
                imageDigest = image_report['imageDigest']
                try:
                    resp = policy_engine_image_load(client, userId, imageId, imageDigest)
                except Exception as err:
                    logger.warn("failed to load image data into policy engine: " + str(err))
            # return the new image:
            return_object = ret_list
            httpcode = 200
        except Exception as err:
            httpcode = 500
            raise err

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)


    return(return_object, httpcode)

def subscriptions(dbsession, request_inputs, subscriptionId=None, bodycontent=None):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    subscription_key_filter = params.get('subscription_key', None)
    subscription_type_filter = params.get('subscription_type', None)

    try:
        logger.debug("looking up subscription record: " + userId + " : " + str(subscriptionId))

        if method == 'GET':

            # set up the filter based on input
            dbfilter = {}
            if subscriptionId:
                dbfilter['subscription_id'] = subscriptionId
            else:
                if subscription_key_filter:
                    dbfilter['subscription_key'] = subscription_key_filter
                if subscription_type_filter:
                    dbfilter['subscription_type'] = subscription_type_filter

            records = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            if not records:
                httpcode = 200
                return_object = []
                #raise Exception("subscriptions not found in DB")
            else:
                return_object = records
                httpcode = 200

        elif method == 'DELETE':
            if not subscriptionId:
                raise Exception("no subscriptionId passed in to delete")

            httpcode = 200
            return_object = True

            subscription_record = db_subscriptions.get(userId, subscriptionId, session=dbsession)
            if subscription_record:
                rc, httpcode = do_subscription_delete(userId, subscription_record, dbsession, force=True)
                if httpcode not in list(range(200,299)):
                    raise Exception(str(rc))

        elif method == 'POST':
            subscriptiondata = bodycontent if bodycontent is not None else {}

            subscription_key = subscription_type = None
            if 'subscription_key' in subscriptiondata:
                subscription_key=subscriptiondata['subscription_key']
            if 'subscription_type' in subscriptiondata:
                subscription_type=subscriptiondata['subscription_type']

            
            if not subscription_key or not subscription_type:
                httpcode = 500
                raise Exception("body does not contain both subscription_key and subscription_type")

            dbfilter = {'subscription_key':subscription_key, 'subscription_type':subscription_type}
            subscription_record = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            if subscription_record:
                httpcode = 500
                raise Exception("subscription already exists in DB")

            rc = db_subscriptions.add(userId, subscription_key, subscription_type, subscriptiondata, session=dbsession)
            return_object = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            httpcode = 200

        elif method == 'PUT':
            subscriptiondata = bodycontent if bodycontent is not None else {}

            subscription_key = subscription_type = None
            if 'subscription_key' in subscriptiondata:
                subscription_key=subscriptiondata['subscription_key']
            if 'subscription_type' in subscriptiondata:
                subscription_type=subscriptiondata['subscription_type']

            
            if not subscription_key or not subscription_type:
                httpcode = 500
                raise Exception("body does not contain both subscription_key and subscription_type")

            dbfilter = {'subscription_key':subscription_key, 'subscription_type':subscription_type}
            subscription_record = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            if not subscription_record:
                httpcode = 404
                raise Exception("subscription to update does not exist in DB")

            rc = db_subscriptions.update(userId, subscription_key, subscription_type, subscriptiondata, session=dbsession)
            return_object = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
            httpcode = 200

    except Exception as err:
        logger.exception('Error handling subscriptions')
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def events(dbsession, request_inputs, bodycontent=None):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        jsondata = {}
        if bodycontent:
            try:
                jsondata = bodycontent
            except Exception as err:
                raise err
        
        if method == 'GET':
            dbfilter = dict()

            if params.get('source_servicename', None):
                dbfilter['source_servicename'] = params.get('source_servicename')

            if params.get('source_hostid', None):
                dbfilter['source_hostid'] = params.get('source_hostid')

            if params.get('resource_type', None):
                dbfilter['resource_type'] = params.get('resource_type')

            if params.get('resource_id', None):
                dbfilter['resource_id'] = params.get('resource_id')

            if params.get('level', None):
                dbfilter['level'] = params.get('level')

            since = None
            if params.get('since', None):
                try:
                    since = dateparser.parse(params.get('since'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value for since query parameter, must be valid datetime string')

            before = None
            if params.get('before', None):
                try:
                    before = dateparser.parse(params.get('before'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value before query parameter, must be valid datetime string')

                if since and since >= before:
                    httpcode = 400
                    raise Exception('Invalid values for since and before query parameters. since must be smaller than before timestamp')

            page = 0
            if params.get('page', None) is not None:
                try:
                    page = int(params.get('page'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value for page query parameter, must be valid integer greater than 0')

            if page < 1:
                httpcode = 400
                raise Exception('page must be a valid integer greater than 0')

            limit = 0
            if params.get('limit', None) is not None:
                try:
                    limit = int(params.get('limit'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value limit query parameter, must be valid integer between 1 and 1000')

            if limit < 1 or limit > 1000:
                httpcode = 400
                raise Exception('limit must be valid integer between 1 and 1000')

            ret = db_events.get_byfilter(userId=userId, session=dbsession, since=since, before=before, page=page, limit=limit, **dbfilter)
            if not ret:
                httpcode = 404
                raise Exception("events not found in DB")
            else:
                return_object = ret
                httpcode = 200

        elif method == 'DELETE':
            dbfilter = dict()

            if params.get('level', None):
                dbfilter['level'] = params.get('level')

            since = None
            if params.get('since', None):
                try:
                    since = dateparser.parse(params.get('since'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value for since query parameter, must be valid datetime string')

            before = None
            if params.get('before', None):
                try:
                    before = dateparser.parse(params.get('before'))
                except:
                    httpcode = 400
                    raise Exception('Invalid value before query parameter, must be valid datetime string')

            ret = db_events.delete_byfilter(userId=userId, session=dbsession, since=since, before=before, **dbfilter)

            httpcode = 200
            return_object = ret

        elif method == 'POST':
            record = db_events.add(session=dbsession, msg=jsondata)

            if record:
                httpcode = 200
                return_object = record

                # Notification for the new event
                try:
                    logger.debug("queueing event creation notification")
                    npayload = {'event': return_object['event']}
                    rc = notifications.queue_notification(userId, subscription_key=return_object['event']['level'], subscription_type='event_log', payload=npayload)
                except Exception as err:
                    logger.warn("failed to enqueue notification for event creation - exception: " + str(err))

            else:
                httpcode = 500
                raise Exception('Cannot create event')
    except Exception as err:
        logger.exception('Error in events handler')
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def events_eventId(dbsession, request_inputs, eventId):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        if method == 'GET':
            ret = db_events.get_byevent_id(userId=userId, eventId=eventId, session=dbsession)
            if not ret:
                httpcode = 404
                raise Exception("Event not found")
            else:
                return_object = ret
                httpcode = 200
        elif method == 'DELETE':
            ret = db_events.delete_byevent_id(userId=userId, eventId=eventId, session=dbsession)
            if not ret:
                httpcode = 404
                raise Exception("Event not found")
            else:
                return_object = True
                httpcode = 200

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)


def archive(dbsession, request_inputs, bucket, archiveid, bodycontent=None):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        if method == 'GET':
            try:
                return_object = json.loads(archive_sys.get(userId, bucket, archiveid))
                httpcode = 200
            except Exception as err:
                httpcode = 404
                raise err

        elif method == 'POST':
            try:
                jsondata = bodycontent
                rc = archive_sys.put(userId, bucket, archiveid, json.dumps(jsondata))
                
                service_records = db_services.get_byname('catalog', session=dbsession)
                if service_records:
                    service_record = service_records[0]
                    resource_url = service_record['base_url'] + "/" + service_record['version'] + "/archive/" + bucket + "/" + archiveid
                else:
                    resource_url = "N/A"

                return_object = resource_url
                httpcode = 200
            except Exception as err:
                httpcode = 500
                raise err
        elif method == 'DELETE':
            try:
                rc = archive_sys.delete(userId, bucket, archiveid)
                httpcode = 200
                return_object = None
            except Exception as err:
                httpcode = 500
                raise err

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)
       
    return(return_object, httpcode)


def system(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        httpcode = 200
        return_object = ['services', 'registries']
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def system_services(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        return_object = service_records
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def system_services_servicename(dbsession, request_inputs, inservicename):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        for service_record in service_records:
            servicename = service_record['servicename']
            if servicename == inservicename:
                return_object.append(service_record)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def system_services_servicename_hostId(dbsession, request_inputs, inservicename, inhostId):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        for service_record in service_records:
            servicename = service_record['servicename']
            if servicename == inservicename:
                hostId = service_record['hostid']
                if hostId == inhostId:
                    if method == 'GET':
                        return_object = [service_record]
                        httpcode = 200
                    elif method == 'DELETE':
                        if service_record['status']:
                            httpcode = 409
                            raise Exception("cannot delete an active service")
                        else:
                            db_services.delete(hostId, servicename, session=dbsession)
                            return_object = True
                            httpcode = 200

        if not return_object:
            httpcode = 404
            raise Exception("servicename/host_id ("+str(inservicename)+"/"+str(inhostId)+") not found in anchore-engine")
            
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def system_registries(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    try:
        if method == 'GET':
            registry_records = db_registries.get_byuserId(userId, session=dbsession)
            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

            return_object = registry_records
            httpcode = 200
        elif method == 'POST':
            registrydata = bodycontent
            validate = params.get('validate', True)

            if 'registry' in registrydata:
                registry=registrydata['registry']
            else:
                httpcode = 500
                raise Exception("body does not contain registry key")

            registry_records = db_registries.get(registry, userId, session=dbsession)
            if registry_records:
                httpcode = 500
                raise Exception("registry already exists in DB")

            localconfig = anchore_engine.configuration.localconfig.get_config()
            if (registrydata['registry_user'] == 'awsauto' or registrydata['registry_pass'] == 'awsauto') and not localconfig['allow_awsecr_iam_auto']:
                httpcode = 406
                raise Exception("'awsauto' is not enabled in service configuration")

            # attempt to validate on registry add before any DB / cred refresh is done - only support docker_v2 registry validation presently at this point
            if validate and registrydata.get('registry_type', False) in ['docker_v2']:
                try:
                    registry_status = docker_registry.ping_docker_registry(registrydata)
                except Exception as err:
                    httpcode = 406
                    raise Exception("cannot ping supplied registry with supplied credentials - exception: {}".format(str(err)))

            rc = db_registries.add(registry, userId, registrydata, session=dbsession)
            registry_records = db_registries.get(registry, userId, session=dbsession)

            try:
                refresh_registry_creds(registry_records, dbsession)

                # perform validation if the refresh/setup is successful
                if validate:
                    for registry_record in registry_records:
                        try:
                            registry_status = docker_registry.ping_docker_registry(registry_records[0])
                        except Exception as err:
                            httpcode = 406
                            raise Exception("cannot ping supplied registry with supplied credentials - exception: {}".format(str(err)))
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))
                # if refresh fails for any reason (and validation is requested), remove the registry from the DB and raise a fault
                if validate:
                    db_registries.delete(registry, userId, session=dbsession)
                    httpcode = 406
                    raise Exception("cannot refresh credentials for supplied registry, with supplied credentials - exception: {}".format(str(err)))

            return_object = registry_records
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def refresh_registry_creds(registry_records, dbsession):

    for registry_record in registry_records:

        logger.debug("checking registry for up-to-date: " + str(registry_record['userId']) + " : " + str(registry_record['registry']) + " : " + str(registry_record['registry_type']))
        if 'registry_type' in registry_record and registry_record['registry_type'] in ['awsecr']:
            if registry_record['registry_type'] == 'awsecr':
                dorefresh = True
                if registry_record['registry_meta']:
                    ecr_data = json.loads(registry_record['registry_meta'])
                    expiresAt = ecr_data['expiresAt']
                    if time.time() < expiresAt:
                        dorefresh =False

                if dorefresh:
                    logger.debug("refreshing ecr registry: " + str(registry_record['userId']) + " : " + str(registry_record['registry']))
                    ecr_data = aws_ecr.refresh_ecr_credentials(registry_record['registry'], registry_record['registry_user'], registry_record['registry_pass'])
                    registry_record['registry_meta'] = json.dumps(ecr_data)
                    db_registries.update_record(registry_record, session=dbsession)

        logger.debug("registry up-to-date: " + str(registry_record['userId']) + " : " + str(registry_record['registry']) + " : " + str(registry_record['registry_type']))
    return(True)

def system_registries_registry(dbsession, request_inputs, registry, bodycontent={}):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    try:
        if method == 'GET':
            registry_records = db_registries.get(registry, userId, session=dbsession)
            if not registry_records:
                httpcode = 404
                raise Exception("registry not found in DB")
            
            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

            return_object = registry_records
            httpcode = 200
        elif method == 'PUT':
            registrydata = bodycontent
            validate = params.get('validate', True)

            registry_record = db_registries.get(registry, userId, session=dbsession)
            if not registry_record:
                httpcode = 404
                raise Exception("could not find existing registry to update")
            
            localconfig = anchore_engine.configuration.localconfig.get_config()
            if (registrydata['registry_user'] == 'awsauto' or registrydata['registry_pass'] == 'awsauto') and not localconfig['allow_awsecr_iam_auto']:
                httpcode = 406
                raise Exception("'awsauto' is not enabled in service configuration")

            if validate:
                try:
                    registry_status = docker_registry.ping_docker_registry(registrydata)
                except Exception as err:
                    httpcode = 406
                    raise Exception("cannot ping supplied registry with supplied credentials - exception: {}".format(str(err)))

            rc = db_registries.update(registry, userId, registrydata, session=dbsession)
            registry_records = db_registries.get(registry, userId, session=dbsession)
            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

            return_object = registry_records
            httpcode = 200
        elif method == 'DELETE':
            if not registry:
                raise Exception("no registryId passed in to delete")

            httpcode = 200
            return_object = True
            
            registry_records = db_registries.get(registry, userId, session=dbsession)
            for registry_record in registry_records:
                rc, httpcode = do_registry_delete(userId, registry_record, dbsession, force=True)
                if httpcode not in list(range(200,299)):
                    raise Exception(str(rc))
                    
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def system_subscriptions(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    try:
        return_object = anchore_engine.common.subscription_types
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)


################################################################################

def perform_vulnerability_scan(userId, imageDigest, dbsession, scantag=None, force_refresh=False):
    # prepare inputs
    try:
        mgr = manager_factory.for_session(dbsession)
        system_user_auth = mgr.get_system_credentials()
        system_userId = system_user_auth[0]
        system_password = system_user_auth[1]

        localconfig = anchore_engine.configuration.localconfig.get_config()
        verify = localconfig['internal_ssl_verify']
        image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)

        annotations = {}
        try:
            if image_record.get('annotations', '{}'):
                annotations = json.loads(image_record.get('annotations', '{}'))
        except Exception as err:
            logger.warn("could not marshal annotations from json - exception: " + str(err))

        if not scantag:
            raise Exception("must supply a scantag")
    except Exception as err:
        raise Exception("could not gather/prepare all necessary inputs for vulnerability - exception: " + str(err))

    client = internal_client_for(PolicyEngineClient, userId)

    imageIds = []
    for image_detail in image_record['image_detail']:
        imageId = image_detail['imageId']
        if imageId and imageId not in imageIds:
            imageIds.append(imageId)


    for imageId in imageIds:
        # do the image load, just in case it was missed in analyze...
        try:
            resp = policy_engine_image_load(client, userId, imageId, imageDigest)
        except Exception as err:
            logger.warn("failed to load image data into policy engine: " + str(err))
            
        curr_vuln_result = client.get_image_vulnerabilities(user_id=userId, image_id=imageId, force_refresh=force_refresh)

        last_vuln_result = {}
        try:
            last_vuln_result = archive_sys.get_document(userId, 'vulnerability_scan', scantag)
        except:
            pass

        # compare them
        doqueue = False

        vdiff = {}
        if last_vuln_result and curr_vuln_result:
            vdiff = anchore_utils.process_cve_status(old_cves_result=last_vuln_result['legacy_report'], new_cves_result=curr_vuln_result['legacy_report'])

        archive_sys.put_document(userId, 'vulnerability_scan', scantag, curr_vuln_result)

        try:
            if vdiff and (vdiff['updated'] or vdiff['added'] or vdiff['removed']):
                logger.debug("detected difference in vulnerability results (current vs last)")
                doqueue = True
            else:
                logger.debug("no difference in vulnerability scan")
        except Exception as err:
            logger.warn("unable to interpret vulnerability difference data - exception: " + str(err))

        # if different, set up a policy eval notification update
        if doqueue:
            try:
                logger.debug("queueing vulnerability update notification")
                npayload = {'diff_vulnerability_result': vdiff}
                if annotations:
                    npayload['annotations'] = annotations

                rc = notifications.queue_notification(userId, scantag, 'vuln_update', npayload)
            except Exception as err:
                logger.warn("failed to enqueue notification - exception: " + str(err))

    return(True)

def perform_policy_evaluation(userId, imageDigest, dbsession, evaltag=None, policyId=None, interactive=False, newest_only=False):
    ret = {}
    # prepare inputs
    try:
        image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)

        annotations = {}
        try:
            if image_record.get('annotations', '{}'):
                annotations = json.loads(image_record.get('annotations', '{}'))
        except Exception as err:
            logger.warn("could not marshal annotations from json - exception: " + str(err))

        if not policyId:
            policy_record = db_policybundle.get_active_policy(userId, session=dbsession)
            policyId = policy_record['policyId']

        policy_bundle = archive_sys.get_document(userId, 'policy_bundles', policyId)
            
        if not evaltag:
            raise Exception("must supply an evaltag")

    except Exception as err:
        raise Exception("could not gather/prepare all necessary inputs for policy evaluation - exception: " + str(err))

    client = internal_client_for(PolicyEngineClient, userId)

    imageId = None
    for image_detail in image_record['image_detail']:
        try:
            imageId = image_detail['imageId']
            break
        except:
            pass


    # do the image load, just in case it was missed in analyze...
    try:
        logger.debug('Reloading image: {}, user: {} digest: {}'.format(imageId, userId, imageDigest))
        resp = policy_engine_image_load(client, userId, imageId, imageDigest)
    except Exception as err:
        logger.warn("failed to load image data into policy engine: " + str(err))

    tagset = [evaltag]
    for fulltag in tagset:
        logger.debug("calling policy_engine: " + str(userId) + " : " + str(imageId) + " : " + str(fulltag))

        try:
            curr_evaluation_result = client.check_user_image_inline(user_id=userId, image_id=imageId, tag=fulltag, policy_bundle=policy_bundle)
        except Exception as err:
            raise err
        curr_final_action = curr_evaluation_result.get('final_action', '').upper()
        
        # set up the newest evaluation
        evalId = hashlib.md5(':'.join([policyId, userId, imageDigest, fulltag, str(curr_final_action)]).encode('utf8')).hexdigest()
        curr_evaluation_record = anchore_engine.common.helpers.make_eval_record(userId, evalId, policyId, imageDigest, fulltag, curr_final_action, "policy_evaluations/" + evalId)

        if interactive:
            logger.debug("interactive eval requested, skipping eval archive store and notification check")
        else:
            # store the newest evaluation
            logger.debug("non-interactive eval requested, performing eval archive store")

            # get last image evaluation
            last_evaluation_record = db_policyeval.tsget_latest(userId, imageDigest, fulltag, session=dbsession)
            last_evaluation_result = {}
            last_final_action = None
            if last_evaluation_record:
                try:
                    last_evaluation_result = archive_sys.get_document(userId, 'policy_evaluations', last_evaluation_record['evalId'])
                    last_final_action = last_evaluation_result['final_action'].upper()
                except:
                    logger.warn("no last eval record - skipping")

            archive_sys.put_document(userId, 'policy_evaluations', evalId, curr_evaluation_result)
            db_policyeval.tsadd(policyId, userId, imageDigest, fulltag, curr_final_action, curr_evaluation_record, session=dbsession)

            # compare last with newest evaluation
            doqueue = False
            if last_evaluation_result and curr_evaluation_result:
                if last_final_action != curr_final_action:
                    logger.debug("detected difference in policy eval results (current vs last)")
                    doqueue = True
                else:
                    logger.debug("no difference in policy evaluation")

            # if different, set up a policy eval notification update
            if doqueue:            
                try:
                    logger.debug("queueing policy eval notification")
                    npayload = {
                        'last_eval': last_evaluation_result,
                        'curr_eval': curr_evaluation_result,
                        }
                    if annotations:
                        npayload['annotations'] = annotations

                    rc = notifications.queue_notification(userId, fulltag, 'policy_eval', npayload)
                except Exception as err:
                    logger.warn("failed to enqueue notification - exception: " + str(err))

        # done

    return(curr_evaluation_record, curr_evaluation_result)

def add_or_update_image(dbsession, userId, imageId, tags=[], digests=[], parentdigest=None, created_at=None, anchore_data=None, dockerfile=None, dockerfile_mode=None, manifest=None, annotations={}):
    ret = []

    logger.debug("adding based on input tags/digests for imageId ("+str(imageId)+") tags="+str(tags)+" digests="+str(digests))

    # input to this section is imageId, list of digests and list of tags (full dig/tag strings with reg/repo[:@]bleh)
    image_ids = {}
    for d in digests:
        image_info = anchore_engine.utils.parse_dockerimage_string(d)
        registry = image_info['registry']
        repo = image_info['repo']
        digest = image_info['digest']
        if not parentdigest:
            parentdigest = digest

        if registry not in image_ids:
            image_ids[registry] = {}
        if repo not in image_ids[registry]:
            image_ids[registry][repo] = {'digests':[], 'tags':[], 'imageId':imageId}
        if digest not in image_ids[registry][repo]['digests']:
            image_ids[registry][repo]['digests'].append(digest)

    for d in tags:
        image_info = anchore_engine.utils.parse_dockerimage_string(d)
        registry = image_info['registry']
        repo = image_info['repo']
        digest = image_info['tag']

        if registry not in image_ids:
            image_ids[registry] = {}
        if repo not in image_ids[registry]:
            image_ids[registry][repo] = {'digests':[], 'tags':[], 'imageId':imageId}
        if digest not in image_ids[registry][repo]['tags']:
            image_ids[registry][repo]['tags'].append(digest)

    if not dockerfile and anchore_data:
        a = anchore_data[0]
        try:
            dockerfile = base64.b64encode(a['image']['imagedata']['image_report']['dockerfile_contents'])
            #dockerfile = a['image']['imagedata']['image_report']['dockerfile_contents'].encode('base64')
            dockerfile_mode = a['image']['imagedata']['image_report']['dockerfile_mode']
        except Exception as err:
            logger.warn("could not extract dockerfile_contents from input anchore_data - exception: " + str(err))
            dockerfile = None
            dockerfile_mode = None

    #logger.debug("rationalized input for imageId ("+str(imageId)+"): " + json.dumps(image_ids, indent=4))
    addlist = {}
    for registry in list(image_ids.keys()):
        for repo in list(image_ids[registry].keys()):
            imageId = image_ids[registry][repo]['imageId']
            digests = image_ids[registry][repo]['digests']
            tags = image_ids[registry][repo]['tags']
            for d in digests:
                fulldigest = registry + "/" + repo + "@" + d
                for t in tags:
                    fulltag = registry + "/" + repo + ":" + t
                    new_image_record = anchore_engine.common.images.make_image_record(userId, 'docker', None, image_metadata={'tag':fulltag, 'digest':fulldigest, 'imageId':imageId, 'parentdigest': parentdigest, 'created_at': created_at, 'dockerfile':dockerfile, 'dockerfile_mode': dockerfile_mode, 'annotations': annotations}, registry_lookup=False, registry_creds=(None, None))
                    imageDigest = new_image_record['imageDigest']
                    image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
                    if not image_record:
                        new_image_record['image_status'] = taskstate.init_state('image_status', None)

                        if anchore_data:
                            rc =  archive_sys.put_document(userId, 'analysis_data', imageDigest, anchore_data)

                            image_content_data = {}
                            for content_type in anchore_engine.common.image_content_types + anchore_engine.common.image_metadata_types:
                                try:
                                    image_content_data[content_type] = anchore_engine.common.helpers.extract_analyzer_content(anchore_data, content_type, manifest=manifest)
                                except:
                                    image_content_data[content_type] = {}
                            if image_content_data:
                                logger.debug("adding image content data to archive")
                                rc = archive_sys.put_document(userId, 'image_content_data', imageDigest, image_content_data)

                            try:
                                logger.debug("adding image analysis data to image_record")
                                anchore_engine.common.helpers.update_image_record_with_analysis_data(new_image_record, anchore_data)
                            except Exception as err:
                                logger.warn("unable to update image record with analysis data - exception: " + str(err))

                            new_image_record['analysis_status'] = taskstate.complete_state('analyze')
                        else:
                            new_image_record['analysis_status'] = taskstate.init_state('analyze', None)

                        try:
                            rc = archive_sys.put_document(userId, 'manifest_data', imageDigest, manifest)

                            rc = db_catalog_image.add_record(new_image_record, session=dbsession)
                            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
                            if not manifest:
                                manifest = json.dumps({})
                        except Exception as err:
                            raise anchore_engine.common.helpers.make_anchore_exception(err, input_message="cannot add image, failed to update archive/DB", input_httpcode=500)

                    else:
                        new_image_detail = anchore_engine.common.images.clean_docker_image_details_for_update(new_image_record['image_detail'])

                        if 'imageId' not in new_image_detail or not new_image_detail['imageId']:
                            for image_detail in image_record['image_detail']:
                                if 'imageId' in image_detail and image_detail['imageId']:
                                    for new_id in new_image_detail:
                                        new_id['imageId'] = image_detail['imageId']
                                    break

                        if dockerfile:
                            for new_id in new_image_detail:
                                new_id['dockerfile'] = dockerfile
                        
                        if dockerfile_mode:
                            image_record['dockerfile_mode'] = dockerfile_mode

                        if annotations:
                            if image_record['annotations']:
                                try:
                                    annotation_data = json.loads(image_record['annotations'])
                                except Exception as err:
                                    logger.warn("could not marshal annotations into json - exception: " + str(err))
                                    annotation_data = {}
                            else:
                                annotation_data = {}

                            try:
                                annotation_data.update(annotations)
                                final_annotation_data = {}
                                for k,v in list(annotation_data.items()):
                                    if v != 'null':
                                        final_annotation_data[k] = v
                                image_record['annotations'] = json.dumps(final_annotation_data)
                            except Exception as err:
                                logger.debug("could not prepare annotations for store - exception: " + str(err))

                        try:
                            rc = archive_sys.put_document(userId, 'manifest_data', imageDigest, manifest)

                            rc = db_catalog_image.update_record_image_detail(image_record, new_image_detail, session=dbsession)
                            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
                            if not manifest:
                                manifest = json.dumps({})
                        except Exception as err:
                            raise anchore_engine.common.helpers.make_anchore_exception(err, input_message="cannot add image, failed to update archive/DB", input_httpcode=500)

                    addlist[imageDigest] = image_record

    #logger.debug("final dict of image(s) to add: " + json.dumps(addlist, indent=4))
    for imageDigest in list(addlist.keys()):
        ret.append(addlist[imageDigest])

    #logger.debug("returning: " + json.dumps(ret, indent=4))
    return(ret)


def do_image_delete(userId, image_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        imageDigest = image_record['imageDigest']
        dodelete = False
        msgdelete = "could not make it though delete checks"
        image_ids = []

        if True:
            # do some checking before delete
            try:
                # check one - don't delete anything that is being analyzed
                if image_record['analysis_status'] == taskstate.working_state('analyze'):
                    if not force:
                        raise Exception("cannot delete image that is being analyzed")

                # check two - don't delete anything that is the latest of any of its tags, and has an active subscription
                for image_detail in image_record['image_detail']:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']

                    if 'imageId' in image_detail and image_detail['imageId']:
                        image_ids.append(image_detail['imageId'])

                    dbfilter = {}
                    dbfilter['registry'] = image_detail['registry']
                    dbfilter['repo'] = image_detail['repo']
                    dbfilter['tag'] = image_detail['tag']

                    latest_image_records = db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter=dbfilter, onlylatest=True, session=dbsession)
                    for latest_image_record in latest_image_records:
                        if latest_image_record['imageDigest'] == image_record['imageDigest']:
                            dbfilter = {}
                            dbfilter['subscription_key'] = fulltag
                            subscription_records = db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
                            for subscription_record in subscription_records:
                                if subscription_record['active']:
                                    if not force:
                                        raise Exception("cannot delete image that is the latest of its tags, and has active subscription")
                                    else:
                                        subscription_record['active'] = False
                                        db_subscriptions.update(userId, subscription_record['subscription_key'], subscription_record['subscription_type'], subscription_record, session=dbsession)

                # checked out - do the delete
                dodelete = True

            except Exception as err:
                msgdelete = str(err)
                dodelete = False

        if dodelete:
            logger.debug("DELETEing image from catalog")
            rc = db_catalog_image.delete(imageDigest, userId, session=dbsession)

            for bucket in ['analysis_data', 'query_data', 'image_content_data', 'image_summary_data', 'manifest_data']:
                logger.debug("DELETEing image from archive " + str(bucket) + "/" + str(imageDigest))
                rc = archive_sys.delete(userId, bucket, imageDigest)

            logger.debug("DELETEing image from policy_engine")

            # prepare inputs
            try:
                pe_client = internal_client_for(PolicyEngineClient, userId=userId)
                for img_id in set(image_ids):
                    logger.debug("DELETING image from policy engine userId = {} imageId = {}".format(userId, img_id))
                    rc = pe_client.delete_image(user_id=userId, image_id=img_id)
            except:
                logger.exception('Failed deleting image from policy engine')
                raise

            return_object = True
            httpcode = 200
        else:
            httpcode = 409
            raise Exception(msgdelete)
    except Exception as err:
        logger.warn("DELETE failed - exception: " + str(err))
        return_object = str(err)

    return(return_object, httpcode)

def do_subscription_delete(userId, subscription_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        dbfilter = {'subscription_id': subscription_record['subscription_id']}
        rc = db_subscriptions.delete_byfilter(userId, remove=True, session=dbsession, **dbfilter)
        if not rc:
            raise Exception("DB delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)

def do_policy_delete(userId, policy_record, dbsession, cleanup_evals=False, force=False):
    return_object = False
    httpcode = 500

    try:
        policyId = policy_record['policyId']

        rc = db_policybundle.delete(policyId, userId, session=dbsession)
        if not rc:
            httpcode = 500
            raise Exception("DB delete of policyId ("+str(policyId)+") failed")
        else:
            if cleanup_evals:
                dbfilter = {"policyId": policyId}
                eval_records = db_policyeval.tsget_byfilter(userId, session=dbsession, **dbfilter)
                for eval_record in eval_records:
                    db_policyeval.delete_record(eval_record, session=dbsession)

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)

def do_evaluation_delete(userId, eval_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        rc = db_policyeval.delete_record(eval_record, session=dbsession)
        if not rc:
            raise Exception("DB update failed")

        httpcode = 200
        return_object = True
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)
        
def do_archive_delete(userId, archive_document, session, force=False):
    return_object = False
    httpcode = 500
    
    try:        
        rc = archive_sys.delete(userId, archive_document['bucket'], archive_document['archiveId'])
        if not rc:
            raise Exception("archive delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)


def do_registry_delete(userId, registry_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        registryId = registry_record['registry']
        rc = db_registries.delete(registryId, userId, session=dbsession)
        if not rc:
            raise Exception("DB delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return(return_object, httpcode)



################################################################################

