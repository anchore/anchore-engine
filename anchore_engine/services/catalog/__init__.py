import json
import os
import copy
import threading
import time
import traceback
import uuid

import connexion
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource
from twisted.web.resource import Resource
from twisted.web import rewrite
from twisted.internet.task import LoopingCall

# anchore modules
from anchore_engine.clients import http, localanchore, simplequeue
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
import anchore_engine.services.common
import anchore_engine.clients.common
from anchore_engine import db
from anchore_engine.db import db_catalog_image, db_eventlog, db_policybundle, db_policyeval, db_queues, db_registries, db_subscriptions, db_users
from anchore_engine.subsys import archive, notifications, taskstate, logger
from anchore_engine.services.catalog import catalog_impl

import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

servicename = 'catalog'
_default_api_version = "v1"

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    flask_app = application.app
    flask_app.url_map.strict_slashes = False
    anchore_engine.subsys.metrics.init_flask_metrics(flask_app, servicename=servicename)
    application.add_api('swagger.yaml')
except Exception as err:
    traceback.print_exc()
    raise err

# service funcs (must be here)

def default_version_rewrite(request):
    global _default_api_version
    try:
        if request.postpath:
            if request.postpath[0] != 'health' and request.postpath[0] != _default_api_version:
                request.postpath.insert(0, _default_api_version)
                request.path = '/'+_default_api_version+request.path
    except Exception as err:
        logger.error("rewrite exception: " +str(err))
        raise err

def createService(sname, config):
    global flask_app, servicename

    servicename = sname

    flask_site = WSGIResource(reactor, reactor.getThreadPool(), application=flask_app)
    realroot = Resource()
    realroot.putChild(b"v1", anchore_engine.services.common.getAuthResource(flask_site, sname, config))
    realroot.putChild(b"health", anchore_engine.services.common.HealthResource())
    # this will rewrite any calls that do not have an explicit version to the base path before being processed by flask
    root = rewrite.RewriterResource(realroot, default_version_rewrite)
    #root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
    return(anchore_engine.services.common.createServiceAPI(root, sname, config))

def initializeService(sname, config):
    service_record = {'hostid': config['host_id'], 'servicename': sname}
    try:
        if not anchore_engine.subsys.servicestatus.has_status(service_record):
            anchore_engine.subsys.servicestatus.initialize_status(service_record, up=True, available=False, message='initializing')
    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("could not initialize service status - exception: " + str(err))

    try:
        rc = archive.initialize()
        if not rc:
            raise Exception("unable to initialize archive: check catalog configuration")

    except Exception as err:
        raise err

    # set up defaults for users if not yet set up
    try:
        with db.session_scope() as dbsession:
            user_records = db.db_users.get_all(session=dbsession)
            for user_record in user_records:
                userId = user_record['userId']
                if userId == 'anchore-system':
                    continue

                bundle_records = db.db_policybundle.get_all_byuserId(userId, session=dbsession)
                if not bundle_records:
                    logger.debug("user has no policy bundle - installing default: " +str(userId))
                    localconfig = anchore_engine.configuration.localconfig.get_config()
                    if 'default_bundle_file' in localconfig and os.path.exists(localconfig['default_bundle_file']):
                        logger.info("loading def bundle: " + str(localconfig['default_bundle_file']))
                        try:
                            default_bundle = {}
                            with open(localconfig['default_bundle_file'], 'r') as FH:
                                default_bundle = json.loads(FH.read())
                            if default_bundle:
                                bundle_url = archive.put_document(userId, 'policy_bundles', default_bundle['id'], default_bundle)
                                policy_record = anchore_engine.services.common.make_policy_record(userId, default_bundle, active=True)
                                rc = db.db_policybundle.add(policy_record['policyId'], userId, True, policy_record, session=dbsession)
                                if not rc:
                                    raise Exception("policy bundle DB add failed")
                        except Exception as err:
                            logger.error("could not load up default bundle for user - exception: " + str(err))
    except Exception as err:
        raise Exception ("unable to initialize default user data - exception: " + str(err))

    # set up monitor
    try:
        kick_timer = int(config['services'][sname]['cycle_timer_seconds'])
    except:
        kick_timer = 1
    try:
        cycle_timers = {}
        cycle_timers.update(config['services'][sname]['cycle_timers'])
    except:
        cycle_timers = {}

    kwargs = {
        'kick_timer':kick_timer,
        'cycle_timers': cycle_timers
    }

    lc = LoopingCall(monitor, **kwargs)
    lc.start(1)
    #catalog._v1.monitor(**kwargs)

    return(anchore_engine.services.common.initializeService(sname, config))

def registerService(sname, config):
    rc = anchore_engine.services.common.registerService(sname, config, enforce_unique=False)

    service_record = {'hostid': config['host_id'], 'servicename': sname}
    anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, update_db=True)

    return (rc)

##########################################################

# monitor section

def handle_feed_sync(*args, **kwargs):
    global feed_sync_updated

    logger.debug("FIRING: feed syncer")
    try:
        all_ready = anchore_engine.clients.common.check_services_ready(['policy_engine'])
        if not all_ready:
            logger.debug("FIRING DONE: feed syncer (skipping due to required services not being available)")
            try:
                kwargs['mythread']['last_return'] = False
            except:
                pass
            return(True)

        with db.session_scope() as dbsession:
            users = db.db_users.get_all(session=dbsession)

        for user in users:
            userId = user['userId']
            if userId == 'anchore-system':
                continue

            # vulnerability scans

            doperform = False
            vuln_sub_tags = []
            for subscription_type in ['vuln_update']:
                dbfilter = {'subscription_type': subscription_type}
                with db.session_scope() as dbsession:
                    subscription_records = db.db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
                for subscription_record in subscription_records:
                    if subscription_record['active']:
                        image_info = anchore_engine.services.common.get_image_info(userId, "docker", subscription_record['subscription_key'], registry_lookup=False, registry_creds=(None, None))
                        dbfilter = {'registry': image_info['registry'], 'repo': image_info['repo'], 'tag': image_info['tag']}
                        if dbfilter not in vuln_sub_tags:
                            vuln_sub_tags.append(dbfilter)

            for dbfilter in vuln_sub_tags:
                with db.session_scope() as dbsession:
                    image_records = db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter=dbfilter, onlylatest=True, session=dbsession)
                for image_record in image_records:
                    if image_record['analysis_status'] == taskstate.complete_state('analyze'):
                        imageDigest = image_record['imageDigest']
                        fulltag = dbfilter['registry'] + "/" + dbfilter['repo'] + ":" + dbfilter['tag']

                        doperform = True
                        if doperform:
                            logger.debug("calling vuln scan perform: " + str(fulltag) + " : " + str(imageDigest))
                            with db.session_scope() as dbsession:
                                try:
                                    rc = catalog_impl.perform_vulnerability_scan(userId, imageDigest, dbsession, scantag=fulltag, force_refresh=False)
                                except Exception as err:
                                    logger.warn("vulnerability scan failed - exception: " + str(err))

    except Exception as err:
        logger.warn("failure in feed sync handler - exception: " + str(err))

    logger.debug("FIRING DONE: feed syncer")

    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass

    return(True)

def handle_history_trimmer(*args, **kwargs):
    logger.debug("FIRING: history trimmer")

    if False:
        try:
            # TODO - deal with configuring these items (per user, via API, via config) - disabled here across the board
            trim_policies = {
                'images': {'prune': False, 'dangling': True, 'olderthan': 6*30*86400},
                'policies': {'prune': False, 'dangling': True, 'olderthan': 6*30*86400},
                'registries': {'prune': False, 'dangling': True, 'olderthan': 6*30*86400},
                'subscriptions': {'prune': False, 'dangling': True, 'olderthan': 6*30*86400},
                'archive': {'prune': False, 'dangling': True, 'olderthan': 6*30*86400},
                'evaluations': {'prune': False, 'dangling': True, 'olderthan': 12*30*86400}
            }

            #trim_policies = {
            #    'images': {'prune': True, 'dangling': True, 'olderthan': 1},
            #    'policies': {'prune': True, 'dangling': True, 'olderthan': 1},
            #    'registries': {'prune': True, 'dangling': True, 'olderthan': 1},
            #    'subscriptions': {'prune': True, 'dangling': True, 'olderthan': 1},
            #    'archive': {'prune': True, 'dangling': True, 'olderthan': 1},
            #    'evaluations': {'prune': True, 'dangling': True, 'olderthan': 1}
            #}

            all_users = []
            with db.session_scope() as dbsession:
                all_users = db.db_users.get_all(session=dbsession)

            for user in all_users:
                userId = user['userId']
                resource_types = anchore_engine.services.common.resource_types
                for resourcetype in resource_types:

                    prune_candidates = {}
                    httpcode = 500

                    try:
                        if resourcetype in trim_policies and trim_policies[resourcetype]['prune']:
                            dangling = trim_policies[resourcetype]['dangling']
                            olderthan = trim_policies[resourcetype]['olderthan']

                            with db.session_scope() as dbsession:
                                prune_candidates, httpcode = catalog_impl.get_prune_candidates(resourcetype, dbsession, dangling=dangling, olderthan=olderthan, resource_user=userId)
                            logger.debug("prune candidates " + str(userId) + " : " + str(resourcetype) + " : " + json.dumps(prune_candidates, indent=4))
                        else:
                            logger.debug("prune policy absent or disabled for resourcetype " + str(resourcetype) + " - skipping")
                    except Exception as err:
                        logger.warn("cannot get prune candidates for userId="+str(userId)+" resourcetype="+str(resourcetype) +  " - exception: " + str(err))
                    else:
                        if httpcode in range(200, 299) and 'prune_candidates' in prune_candidates and prune_candidates['prune_candidates']:
                            # TODO do the prune
                            prunes = {}
                            httpcode = 500

                            with db.session_scope() as dbsession:
                                prunes, httpcode = catalog_impl.delete_prune_candidates(resourcetype, prune_candidates, dbsession, resource_user=userId)

                            logger.debug("the prune resulted in: " + str(httpcode) + " : " + json.dumps(prunes))
                            if prunes:
                                logger.debug("pruned: " + json.dumps(prunes, indent=4))
                        else:
                            logger.debug("skipping pruning: " + str(userId) + " : " + str(resourcetype) + " : " + str(httpcode) + " : " + str(prune_candidates))

        except Exception as err:
            logger.warn("failure in history trimmer: " + str(err))

    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass

    logger.debug("FIRING DONE: history trimmer")

    return(True)

def handle_service_watcher(*args, **kwargs):
    #global latest_service_records

    logger.debug("ENTERING: " + str(kwargs))
    cycle_timer = kwargs['mythread']['cycle_timer']
    max_service_heartbeat_timer = 300

    while(True):
        logger.debug("FIRING: service watcher: " + str(kwargs))

        localconfig = anchore_engine.configuration.localconfig.get_config()
        verify = localconfig['internal_ssl_verify']

        with db.session_scope() as dbsession:
            system_user = db.db_users.get('anchore-system', session=dbsession)
            userId = system_user['userId']
            password = system_user['password']

            anchore_services = db.db_services.get_all(session=dbsession)
            # update the global latest service record dict in services.common
            #latest_service_records.update({"service_records": copy.deepcopy(anchore_services)})

            # fields to update each tick:
            #
            # heartbeat (current time)
            # status (true/false)
            # status_message (state of service)
            # short_description(api return)
            #

            for service in anchore_services:
                service_update_record = {}
                if service['servicename'] == 'catalog' and service['hostid'] == localconfig['host_id']:
                    status = anchore_engine.subsys.servicestatus.get_status(service)
                    service_update_record.update({'heartbeat': int(time.time()), 'status': True, 'status_message': taskstate.complete_state('service_status'), 'short_description': json.dumps(status)})
                else:
                    #url = '/'.join([service['base_url'], service['version'], 'status'])
                    try:
                        #status = http.anchy_get(url, auth=(userId, password), verify=verify, timeout=30)
                        try:
                            status = json.loads(service['short_description'])
                        except:
                            status = {'up': False, 'available': False}
                            
                        #service_update_record['heartbeat'] = int(time.time())
                        # set to down until the response can be parsed
                        service_update_record['status'] = False                    
                        service_update_record['status_message'] = taskstate.fault_state('service_status')
                        service_update_record['short_description'] = "could not get service status description"

                        try:
                            # NOTE: this is where any service-specific decisions based on the 'status' record could happen - now all services are the same
                            #if False:
                            if status['up'] and status['available']:
                                if time.time() - service['heartbeat'] > max_service_heartbeat_timer:
                                    logger.warn("no service heartbeat within allowed time period ("+str([service['hostid'], service['base_url']]) + " - disabling service")
                                    service_update_record['short_description'] = "no heartbeat from service"
                                else:
                                    service_update_record['status'] = True
                                    service_update_record['status_message'] = taskstate.complete_state('service_status')
                                    try:
                                        service_update_record['short_description'] = json.dumps(status)
                                    except:
                                        service_update_record['short_description'] = str(status)
                        except Exception as err:
                            logger.warn("could not get/parse service status record for service: - exception: " + str(err))

                    except Exception as err:
                        logger.warn("could not get service status: " + str(service) + " : exception: " + str(err) + " : " + str(err.__dict__))
                        service_update_record['status'] = False
                        service_update_record['status_message'] = taskstate.fault_state('service_status')
                        service_update_record['short_description'] = "could not get service status"

                if service_update_record:
                    service.update(service_update_record)
                    try:
                        db.db_services.update_record(service, session=dbsession)
                    except Exception as err:
                        logger.warn("could not update DB: " + str(err))
                else:
                    logger.warn("no service_update_record populated - nothing to update")

        #with db.session_scope() as dbsession:
        #    anchore_services = db.db_services.get_all(session=dbsession)
        #    # update the global latest service record dict in services.common
        #    latest_service_records.update({"service_records": copy.deepcopy(anchore_services)})


        if False:
            with db.session_scope() as dbsession:
                anchore_services = db.db_services.get_all(session=dbsession)
                logger.debug("checking for expired service entries")
                expire_time = (kwargs['mythread']['cycle_timer'] * 2) + 10
                for service in anchore_services:
                    logger.debug("service update delta: " + str(time.time() - service['last_updated']) + " : " + str(expire_time))
                    if service['base_url'] and service['base_url'] != 'N/A':
                        if (time.time() - service['last_updated']) > expire_time:
                            logger.debug("clearing expired service entry: " + str(service))
                            db.db_services.delete(service['hostid'], service['servicename'], session=dbsession)

        logger.debug("FIRING DONE: service watcher")
        try:
            kwargs['mythread']['last_return'] = True
        except:
            pass

        time.sleep(cycle_timer)
    return(True)

def handle_repo_watcher(*args, **kwargs):
    global system_user_auth

    logger.debug("FIRING: repo watcher")
    with db.session_scope() as dbsession:
        users = db.db_users.get_all(session=dbsession)

    for user in users:
        userId = user['userId']
        if userId == 'anchore-system':
            continue

        dbfilter = {}
        with db.session_scope() as dbsession:
            dbfilter['subscription_type'] = 'repo_update'
            subscription_records = db.db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)

            registry_creds = db.db_registries.get_byuserId(userId, session=dbsession)
            try:
                catalog_impl.refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

        for subscription_record in subscription_records:
            if not subscription_record['active']:
                continue

            try:
                regrepo = subscription_record['subscription_key']
                if subscription_record['subscription_value']:
                    subscription_value = json.loads(subscription_record['subscription_value'])
                    if 'autosubscribe' not in subscription_value:
                        subscription_value['autosubscribe'] = False
                    if 'lookuptag' not in subscription_value:
                        subscription_value['lookuptag'] = 'latest'
                    
                else:
                    subscription_value = {'autosubscribe': False, 'lookuptag': 'latest'}

                stored_repotags = subscription_value.get('repotags', [])

                fulltag = regrepo + ":" + subscription_value.get('lookuptag', 'latest')
                image_info = anchore_engine.services.common.get_image_info(userId, "docker", fulltag, registry_lookup=False, registry_creds=(None, None))
                curr_repotags = anchore_engine.auth.docker_registry.get_repo_tags(userId, image_info, registry_creds=registry_creds)

                autosubscribes = ['analysis_update']
                if subscription_value['autosubscribe']:
                    autosubscribes.append("tag_update")

                repotags = set(curr_repotags).difference(set(stored_repotags))
                if repotags:
                    logger.debug("new tags to watch in repo ("+str(regrepo)+"): " + str(repotags))
                    added_repotags = stored_repotags
                    
                    for repotag in repotags:
                        try:
                            fulltag = image_info['registry'] + "/" + image_info['repo'] + ":" + repotag
                            logger.debug("found new tag in repo: " + str(fulltag))
                            new_image_info = anchore_engine.services.common.get_image_info(userId, "docker", fulltag, registry_lookup=True, registry_creds=registry_creds)
                            manifest = None
                            try:
                                if 'manifest' in new_image_info:
                                    manifest = json.dumps(new_image_info['manifest'])
                                else:
                                    raise Exception("no manifest from get_image_info")
                            except Exception as err:
                                raise Exception("could not fetch/parse manifest - exception: " + str(err))

                            with db.session_scope() as dbsession:
                                logger.debug("adding/updating image from repo scan " + str(new_image_info['fulltag']))

                                # add the image
                                image_records = catalog_impl.add_or_update_image(dbsession, userId, new_image_info['imageId'], tags=[new_image_info['fulltag']], digests=[new_image_info['fulldigest']], manifest=manifest)
                                # add the subscription records with the configured default activations

                                for stype in anchore_engine.services.common.subscription_types:
                                    activate = False
                                    if stype == 'repo_update':
                                        continue
                                    elif stype in autosubscribes:
                                        activate = True
                                    db_subscriptions.add(userId, new_image_info['fulltag'], stype, {'active': activate}, session=dbsession)

                            added_repotags.append(repotag)
                        except Exception as err:
                            logger.warn("could not add discovered tag from repo ("+str(fulltag)+") - exception: " + str(err))

                    # update the subscription record with the latest successfully added image tags
                    with db.session_scope() as dbsession:
                        subscription_value['repotags'] = added_repotags
                        subscription_value['tagcount'] = len(added_repotags)
                        db_subscriptions.update(userId, regrepo, 'repo_update', {'subscription_value': json.dumps(subscription_value)}, session=dbsession)

                else:
                    logger.debug("no new images in watched repo ("+str(regrepo)+"): skipping")
            except Exception as err:
                logger.warn("failed to process repo_update subscription - exception: " + str(err))

    logger.debug("FIRING DONE: repo watcher")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)

def handle_image_watcher(*args, **kwargs):
    global system_user_auth

    logger.debug("FIRING: image watcher")
    with db.session_scope() as dbsession:
        users = db.db_users.get_all(session=dbsession)

    for user in users:
        userId = user['userId']
        if userId == 'anchore-system':
            continue

        with db.session_scope() as dbsession:
            dbfilter = {}
            dbfilter['subscription_type'] = 'tag_update'
            subscription_records = db.db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)

            registry_creds = db.db_registries.get_byuserId(userId, session=dbsession)
            try:
                catalog_impl.refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn("failed to refresh registry credentials - exception: " + str(err))

        alltags = []
        for subscription_record in subscription_records:
            if not subscription_record['active']:
                continue

            if True:
                try:
                    fulltag = subscription_record['subscription_key']
                    if fulltag not in alltags:
                        alltags.append(fulltag)

                except Exception as err:
                    logger.warn("problem creating taglist for image watcher - exception: " + str(err))

        for registry_record in registry_creds:
            registry_status = anchore_engine.auth.docker_registry.ping_docker_registry(registry_record)
            if not registry_status:
                registry_record['record_state_key'] = 'auth_failure'
                registry_record['record_state_val'] = str(int(time.time()))
                
        logger.debug("checking tags for update: " + str(userId) + " : " + str(alltags))
        for fulltag in alltags:
            try:
                logger.debug("checking image latest info from registry: " + fulltag)

                image_info = anchore_engine.services.common.get_image_info(userId, "docker", fulltag, registry_lookup=True, registry_creds=registry_creds)
                logger.spew("checking image: got registry info: " + str(image_info))

                manifest = None
                try:
                    if 'manifest' in image_info:
                        manifest = json.dumps(image_info['manifest'])
                    else:
                        raise Exception("no manifest from get_image_info")
                except Exception as err:
                    manifest=None
                    raise Exception("could not fetch/parse manifest - exception: " + str(err))

                try:
                    dbfilter = {
                        'registry': image_info['registry'],
                        'repo': image_info['repo'],
                        'tag': image_info['tag'],
                        'digest': image_info['digest']
                    }
                except Exception as err:
                    raise Exception("could not prepare db filter for complete lookup check - exception: " + str(err))

                try:
                    stored_manifest = json.loads(archive.get_document(userId, 'manifest_data', image_info['digest']))
                    if not stored_manifest:
                        raise Exception("stored manifest is empty")
                except Exception as err:
                    logger.debug("found empty/invalid stored manifest, storing new: " + str(err))
                    rc = archive.put_document(userId, 'manifest_data', image_info['digest'], manifest)

                logger.debug("checking image: looking up image in db using dbfilter: " + str(dbfilter))
                with db.session_scope() as dbsession:
                    record = db.db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter, session=dbsession)
                if record:
                    logger.debug("checking image: found match, no update, nothing to do: " + str(fulltag))
                else:
                    logger.info("checking image: found latest digest for tag is not in DB: should update and queue for analysis: tag="+str(fulltag) + " latest_digest="+str(dbfilter['digest']))
                    # get the set of existing digests
                    try:
                        last_dbfilter = {}
                        last_dbfilter.update(dbfilter)
                        last_dbfilter.pop('digest', None)

                        last_digests = []
                        last_annotations = {}
                        is_latest = True
                        with db.session_scope() as dbsession:
                            last_image_records = db.db_catalog_image.get_byimagefilter(userId, 'docker', last_dbfilter, session=dbsession)

                        if last_image_records:
                            for last_image_record in last_image_records:
                                imageDigest = last_image_record['imageDigest']
                                for image_detail in last_image_record['image_detail']:
                                    last_digests.append(image_detail['digest'])

                                # only do this (bring forward annotations) for the first found digest (last digest associated with tag)
                                if is_latest:
                                    if not last_annotations and last_image_record['annotations']:
                                        try:
                                            last_annotations.update(json.loads(last_image_record['annotations']))
                                        except:
                                            pass
                                    is_latest = False

                    except Exception as err:
                        logger.error(str(err))

                    # add and store the new image
                    with db.session_scope() as dbsession:
                        logger.debug("adding new image from tag watcher " + str(image_info))
                        image_records = catalog_impl.add_or_update_image(dbsession, userId, image_info['imageId'], tags=[image_info['fulltag']], digests=[image_info['fulldigest']], manifest=manifest, annotations=last_annotations)

                    if image_records:
                        image_record = image_records[0]
                    else:
                        image_record = {}

                    logger.info("checking image: added new image: " + str(image_record))
                    new_digests = [image_info['digest']]

                    # construct the notification and queue
                    try:
                        npayload = {
                            'last_eval': last_digests,
                            'curr_eval': new_digests,
                        }
                        rc = notifications.queue_notification(userId, fulltag, 'tag_update', npayload)
                        logger.debug("queued image tag update notification: " + fulltag)

                        #inobj = {
                        #    'userId': userId,
                        #    'subscription_key':fulltag,
                        #    'notificationId': str(uuid.uuid4()),
                        #    'last_eval':last_digests,
                        #    'curr_eval':new_digests,
                        #}
                        #if not simplequeue.is_inqueue(system_user_auth, 'tag_update', inobj):
                        #    qobj = simplequeue.enqueue(system_user_auth, 'tag_update', inobj)
                        #    logger.debug("queued image tag update notification: " + fulltag)

                    except Exception as err:
                        logger.error("failed to queue tag update notification - exception: " +str(err))
                        raise err

            except Exception as err:
                logger.error("failed to check/update image - exception: " + str(err))

    logger.debug("FIRING DONE: image watcher")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)

def check_feedmeta_update(dbsession):
    global feed_sync_updated
    return(feed_sync_updated)

def check_policybundle_update(userId, dbsession):
    global bundle_user_last_updated

    is_updated = True

    try:
        last_bundle_update = 0
        active_policy_record = db.db_policybundle.get_active_policy(userId, session=dbsession)
        if active_policy_record:
            last_bundle_update = active_policy_record['last_updated']
        else:
            logger.warn("user has no active policy - queueing just in case" + str(userId))
            return(is_updated)

        if userId not in bundle_user_last_updated:
            bundle_user_last_updated[userId] = last_bundle_update

        if last_bundle_update == bundle_user_last_updated[userId]:
            logger.debug("no bundle update detected since last cycle")
            is_updated = False
        else:
            logger.debug("bundle update detected since last cycle")
            bundle_user_last_updated[userId] = last_bundle_update
            is_updated = True
    except Exception as err:
        logger.warn("failed to get/parse active policy bundle for user ("+str(userId)+") - exception: " + str(err))
        bundle_user_last_updated[userId] = 0
        is_updated = True

    return(is_updated)

def handle_policyeval(*args, **kwargs):
    global system_user_auth, bundle_user_is_updated, feed_sync_updated
    logger.debug("FIRING: policy eval / vuln scan")

    try:
        all_ready = anchore_engine.clients.common.check_services_ready(['policy_engine', 'simplequeue'])
        if not all_ready:
            logger.debug("FIRING DONE: policy eval (skipping due to required services not being available)")
            try:
                kwargs['mythread']['last_return'] = False
            except:
                pass
            return(True)

        with db.session_scope() as dbsession:
            feed_updated = check_feedmeta_update(dbsession)
            users = db.db_users.get_all(session=dbsession)

        for user in users:
            userId = user['userId']
            if userId == 'anchore-system':
                continue

            # policy evaluations

            doperform = False
            policy_sub_tags = []
            for subscription_type in ['policy_eval']:
                dbfilter = {'subscription_type': subscription_type}
                with db.session_scope() as dbsession:
                    subscription_records = db.db_subscriptions.get_byfilter(userId, session=dbsession, **dbfilter)
                for subscription_record in subscription_records:
                    if subscription_record['active']:
                        image_info = anchore_engine.services.common.get_image_info(userId, "docker", subscription_record['subscription_key'], registry_lookup=False, registry_creds=(None, None))
                        dbfilter = {'registry': image_info['registry'], 'repo': image_info['repo'], 'tag': image_info['tag']}
                        if dbfilter not in policy_sub_tags:
                            policy_sub_tags.append(dbfilter)

            for dbfilter in policy_sub_tags:
                with db.session_scope() as dbsession:
                    image_records = db_catalog_image.get_byimagefilter(userId, 'docker', dbfilter=dbfilter, onlylatest=True, session=dbsession)
                for image_record in image_records:
                    if image_record['analysis_status'] == taskstate.complete_state('analyze'):
                        imageDigest = image_record['imageDigest']
                        fulltag = dbfilter['registry'] + "/" + dbfilter['repo'] + ":" + dbfilter['tag']

                        # TODO - checks to avoid performing eval if nothing has changed
                        doperform = True
                        if doperform:
                            logger.debug("calling policy eval perform: " + str(fulltag) + " : " + str(imageDigest))
                            with db.session_scope() as dbsession:
                                try:
                                    rc = catalog_impl.perform_policy_evaluation(userId, imageDigest, dbsession, evaltag=fulltag)
                                except Exception as err:
                                    logger.warn("policy evaluation failed - exception: " + str(err))

    except Exception as err:
        logger.warn("failure in policy eval / vuln scan handler - exception: " + str(err))

    logger.debug("FIRING DONE: policy eval / vuln scan")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)    

def handle_analyzer_queue(*args, **kwargs):
    global system_user_auth

    localconfig = anchore_engine.configuration.localconfig.get_config()
    try:
        max_working_time = int(localconfig['image_analyze_timeout_seconds'])
    except:
        max_working_time = 36000

    logger.debug("FIRING: analyzer queuer")
    
    all_ready = anchore_engine.clients.common.check_services_ready(['policy_engine', 'simplequeue'])
    if not all_ready:
        logger.debug("FIRING DONE: analyzer queuer (skipping due to required services not being available)")
        try:
            kwargs['mythread']['last_return'] = False
        except:
            pass
        return(True)

    with db.session_scope() as dbsession:
        users = db.db_users.get_all(session=dbsession)

    for user in users:
        userId = user['userId']
        if userId == 'anchore-system':
            continue
            
        # do this in passes, for each analysis_status state

        with db.session_scope() as dbsession:
            dbfilter = {'analysis_status': taskstate.working_state('analyze')}
            workingstate_image_records = db.db_catalog_image.get_byfilter(userId, session=dbsession, **dbfilter)

        # first, evaluate images looking for those that have been in working state for too long and reset
        for image_record in workingstate_image_records:
            imageDigest = image_record['imageDigest']
            if image_record['image_status'] == taskstate.complete_state('image_status'):
                state_time = int(time.time()) - image_record['last_updated']
                logger.debug("image in working state for ("+str(state_time)+")s - "+str(imageDigest))
                if state_time > max_working_time:
                    logger.warn("image has been in working state ("+str(taskstate.working_state('analyze'))+") for over ("+str(max_working_time)+") seconds - resetting and requeueing for analysis")
                    image_record['analysis_status'] = taskstate.reset_state('analyze')
                    with db.session_scope() as dbsession:
                        db.db_catalog_image.update_record(image_record, session=dbsession)

        # next, look for any image in base state (not_analyzed) for queuing
        with db.session_scope() as dbsession:
            dbfilter = {'analysis_status': taskstate.base_state('analyze')}
            #dbfilter = {}
            basestate_image_records = db.db_catalog_image.get_byfilter(userId, session=dbsession, **dbfilter)

        for image_record in basestate_image_records:
            imageDigest = image_record['imageDigest']
            if image_record['image_status'] == taskstate.complete_state('image_status'):
                logger.debug("image check")
                if image_record['analysis_status'] == taskstate.base_state('analyze'):
                    logger.debug("image in base state - "+str(imageDigest))
                    try:
                        manifest = archive.get_document(userId, 'manifest_data', image_record['imageDigest'])
                    except Exception as err:
                        manifest = {}

                    qobj = {}
                    qobj['userId'] = userId
                    qobj['imageDigest'] = image_record['imageDigest']
                    qobj['manifest'] = manifest
                    try:
                        if not simplequeue.is_inqueue(system_user_auth, 'images_to_analyze', qobj):
                            # queue image for analysis
                            logger.debug("queued image for analysis: " + str(imageDigest))
                            qobj = simplequeue.enqueue(system_user_auth, 'images_to_analyze', qobj)

                            # set the appropriate analysis state for image 
                            #image_record['analysis_status'] = taskstate.queued_state('analyze')
                            #image_record['analysis_status'] = taskstate.working_state('analyze')
                            #with db.session_scope() as dbsession:
                            #    rc = db.db_catalog_image.update_record(image_record, session=dbsession)

                        else:
                            logger.debug("image already queued")
                    except Exception as err:
                        logger.error("failed to check/queue image for analysis - exception: " + str(err))
                
    logger.debug("FIRING DONE: analyzer queuer")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)

def handle_policy_bundle_sync(*args, **kwargs):
    global system_user_auth, bundle_user_last_updated

    localconfig = anchore_engine.configuration.localconfig.get_config()

    logger.debug("FIRING: policy_bundle_sync")
    with db.session_scope() as dbsession:
        users = db.db_users.get_all(session=dbsession)
        for user in users:
            userId = user['userId']
            if userId == 'anchore-system':
                continue

            try:
                autosync = False
                try:
                    autosync = localconfig['credentials']['users'][userId]['auto_policy_sync']
                except:
                    pass

                if not autosync:
                    logger.debug("user ("+str(userId)+") has auto_policy_sync set to false in config - skipping bundle sync")
                    continue
                else:
                    logger.debug("user ("+str(userId)+") has auto_policy_sync set to true in config - attempting bundle sync")

                anchorecredstr = localconfig['credentials']['users'][userId]['external_service_auths']['anchoreio']['anchorecli']['auth']
                anchore_user, anchore_pw = anchorecredstr.split(':')

                with localanchore.get_anchorelock():
                    anchore_user_bundle = localanchore.get_bundle(anchore_user, anchore_pw)

                try:
                    import anchore.anchore_policy
                    rc = anchore.anchore_policy.verify_policy_bundle(bundle=anchore_user_bundle)
                    if not rc:
                        raise Exception("input bundle does not conform to anchore bundle schema")
                except Exception as err:
                    raise Exception("cannot run bundle schema verification - exception: " + str(err))

                # TODO should compare here to determine if new bundle is different from stored/active bundle
                do_update = True
                try:
                    current_policy_record = db.db_policybundle.get_active_policy(userId, session=dbsession)
                    if current_policy_record:
                        current_policy_bundle = archive.get_document(userId, 'policy_bundles', current_policy_record['policyId'])
                        if current_policy_bundle and current_policy_bundle == anchore_user_bundle:
                            logger.debug("synced bundle is the same as currently installed/active bundle")
                            do_update = False

                            # special case for upgrade when adding the policy_source column
                            try:
                                if current_policy_record['policy_source'] == 'local':
                                    logger.debug("upgrade case detected - need to write policy_source as anchoreio for existing policy bundle")
                                    do_update = True
                            except:
                                pass

                        else:
                            logger.debug("synced bundle is different from currently installed/active bundle")
                            do_update = True
                except Exception as err:
                    logger.warn("unable to compare synced bundle with current bundle: " + str(err))


                if do_update:

                    logger.spew("synced bundle object: " + json.dumps(anchore_user_bundle, indent=4))
                    new_policybundle_record = anchore_engine.services.common.make_policy_record(userId, anchore_user_bundle, policy_source="anchore.io", active=True)
                    logger.spew("created new bundle record: " + json.dumps(new_policybundle_record, indent=4))

                    policyId = new_policybundle_record['policyId']
                    rc = archive.put_document(userId, 'policy_bundles', policyId, anchore_user_bundle)
                    logger.debug("bundle record archived: " + str(userId) + " : " + str(policyId))
                    rc = db.db_policybundle.update(policyId, userId, True, new_policybundle_record, session=dbsession)
                    logger.debug("bundle record stored: " + str(userId) + " : " + str(policyId))
                    if not rc:
                        raise Exception("DB update failed")
                    else:
                        rc = db.db_policybundle.set_active_policy(policyId, userId, session=dbsession)
                        bundle_user_last_updated[userId] = 0
            except Exception as err:
                logger.warn("no valid bundle available for user ("+str(userId)+") - exception: " + str(err))

    logger.debug("FIRING DONE: policy_bundle_sync")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)

def handle_notifications(*args, **kwargs):
    global system_user_auth

    logger.debug("FIRING: notifier")
    with db.session_scope() as dbsession:
        # special handling of the error event queue, if configured as a webhook
        try:
            localconfig = anchore_engine.configuration.localconfig.get_config()
            try:
                notification_timeout = int(localconfig['webhooks']['notification_retry_timeout'])
            except:
                notification_timeout = 30

            logger.debug("notification timeout: " + str(notification_timeout))

            do_erreventhooks = False
            try:
                if localconfig['webhooks']['error_event']:
                    do_erreventhooks = True
            except:
                logger.debug("error_event webhook is not configured, skipping webhook for error_event")

            if do_erreventhooks:
                system_user_record = db.db_users.get('admin', session=dbsession)
                errevent_records = db.db_eventlog.get_all(session=dbsession)
                for errevent in errevent_records:
                    notification = errevent
                    userId = system_user_record['userId']
                    notificationId = str(uuid.uuid4())
                    subscription_type = 'error_event'
                    notification_record = notifications.make_notification(system_user_record, 'error_event', notification)
                    logger.spew("Storing NOTIFICATION: " + str(system_user_record) + str(notification_record))
                    db.db_queues.add(subscription_type, userId, notificationId, notification_record, 0, int(time.time() + notification_timeout), session=dbsession)
                    db.db_eventlog.delete_record(errevent, session=dbsession)
        except Exception as err:
            logger.warn("failed to queue error eventlog for notification - exception: " + str(err))

        # regular event queue notifications
        for subscription_type in anchore_engine.services.common.subscription_types + ['error_event']:
            logger.debug("notifier: " + subscription_type)
            users = db.db_users.get_all(session=dbsession)

            try:
                qlen = simplequeue.qlen(system_user_auth, subscription_type)
            except Exception as err:
                logger.debug("problem looking for notifications in queue: " + str(subscription_type) + " - exception: " + str(err))
                qlen = 0

            while(qlen > 0):
                pupdate_record = simplequeue.dequeue(system_user_auth, subscription_type)
                if pupdate_record:
                    logger.debug("got notification from queue: " + json.dumps(pupdate_record, indent=4))
                    notification = pupdate_record['data']
                    userId = notification['userId']
                    subscription_key = notification['subscription_key']
                    notificationId = notification['notificationId']
                    for user in users:
                        try:
                            if userId == user['userId']:
                                dbfilter = {'subscription_type': subscription_type, 'subscription_key': subscription_key}
                                subscription_records = db.db_subscriptions.get_byfilter(user['userId'], session=dbsession, **dbfilter)
                                if subscription_records:
                                    subscription = subscription_records[0]
                                    if subscription and subscription['active']:
                                        notification_record = notifications.make_notification(user, subscription_type, notification)
                                        logger.spew("Storing NOTIFICATION: " + str(user) + str(notification_record))
                                        db.db_queues.add(subscription_type, userId, notificationId, notification_record, 0, int(time.time() + notification_timeout), session=dbsession)

                        except Exception as err:
                            import traceback
                            traceback.print_exc()
                            logger.warn("cannot store notification to DB - exception: " + str(err))

                qlen = simplequeue.qlen(system_user_auth, subscription_type)

            for user in users:
                notification_records = db.db_queues.get_all(subscription_type, user['userId'], session=dbsession)
                for notification_record in notification_records:
                    logger.debug("drained to send: " + json.dumps(notification_record))
                    try:
                        rc = notifications.notify(user, notification_record)
                        if rc:
                            db.db_queues.delete_record(notification_record, session=dbsession)
                    except Exception as err:
                        logger.debug("failed to send notification, storing for retry - exception: " + str(err))
                        notification_record['tries'] = int(time.time())
                        if notification_record['tries'] > notification_record['max_tries']:
                            logger.error("hit max notification timeout: dropping notificaion")
                            db.db_queues.delete_record(notification_record, session=dbsession)
                        else:
                            db.db_queues.update_record(notification_record, session=dbsession)

    logger.debug("FIRING DONE: notifier")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass
    return(True)

def handle_metrics(*args, **kwargs):
    cycle_timer = kwargs['mythread']['cycle_timer']

    while(True):

        # perform some DB read/writes for metrics gathering
        if anchore_engine.subsys.metrics.is_enabled():

            # DB probes
            anchore_record = None
            try:
                with anchore_engine.subsys.metrics.get_summary_obj("anchore_db_read_seconds").time() as mtimer:
                    with db.session_scope() as dbsession:
                        anchore_record = db.db_anchore.get(session=dbsession)
            except Exception as err:
                logger.warn("unable to perform DB read probe - exception: " + str(err))

            if anchore_record:
                try:
                    with anchore_engine.subsys.metrics.get_summary_obj("anchore_db_write_seconds").time() as mtimer:
                        with db.session_scope() as dbsession:
                            anchore_record['record_state_val'] = str(time.time())
                            rc = db.db_anchore.update_record(anchore_record, session=dbsession)

                except Exception as err:
                    logger.warn("unable to perform DB write probe - exception: " + str(err))

            try:
                with anchore_engine.subsys.metrics.get_summary_obj("anchore_db_readwrite_seconds").time() as mtimer:
                    with db.session_scope() as dbsession:
                        anchore_record = db.db_anchore.get(session=dbsession)
                        anchore_record['record_state_val'] = str(time.time())
                        rc = db.db_anchore.update_record(anchore_record, session=dbsession)
            except Exception as err:
                logger.warn("unable to perform DB read/write probe - exception: " + str(err))


            # FS probes
            localconfig = anchore_engine.configuration.localconfig.get_config()
            try:
                tmpdir = localconfig['tmp_dir']
                svfs = os.statvfs(tmpdir)
                available_bytes = svfs.f_bsize * svfs.f_bavail
                anchore_engine.subsys.metrics.gauge_set("anchore_tmpspace_available_bytes", available_bytes)
            except Exception as err:
                logger.warn("unable to detect available bytes probe - exception: " + str(err))

        time.sleep(cycle_timer)

def handle_catalog_duty (*args, **kwargs):
    global system_user_auth

    import anchore_engine.auth.aws_ecr

    logger.debug("FIRING: catalog duty cycle")
    logger.debug("FIRING DONE: catalog duty cycle")
    try:
        kwargs['mythread']['last_return'] = True
    except:
        pass

    return(True)

click = 0
running = False
last_run = 0
system_user_auth = ('anchore-system', '')
# policy update check data
feed_sync_updated = False
bundle_user_last_updated = {}
bundle_user_is_updated = {}

watchers = {
    'image_watcher': {'handler': handle_image_watcher, 'task_lease_id': 'image_watcher', 'taskType': 'handle_image_watcher', 'args': [], 'cycle_timer': 600, 'min_cycle_timer': 300, 'max_cycle_timer': 86400*7, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'repo_watcher': {'handler': handle_repo_watcher, 'task_lease_id': 'repo_watcher', 'taskType': 'handle_repo_watcher', 'args': [], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 86400*7, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'policy_eval': {'handler':handle_policyeval, 'task_lease_id': 'policy_eval', 'taskType': 'handle_policyeval', 'args': [], 'cycle_timer': 10, 'min_cycle_timer': 5, 'max_cycle_timer': 86400*2, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'policy_bundle_sync': {'handler':handle_policy_bundle_sync, 'task_lease_id': 'policy_bundle_sync','taskType': 'handle_policy_bundle_sync', 'args': [], 'cycle_timer': 3600, 'min_cycle_timer': 300, 'max_cycle_timer': 86400*2, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'analyzer_queue': {'handler':handle_analyzer_queue, 'task_lease_id': 'analyzer_queue','taskType': 'handle_analyzer_queue', 'args': [], 'cycle_timer': 5, 'min_cycle_timer': 1, 'max_cycle_timer': 7200, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'notifications': {'handler':handle_notifications, 'task_lease_id': 'notifications','taskType': 'handle_notifications', 'args': [], 'cycle_timer': 10, 'min_cycle_timer': 10, 'max_cycle_timer': 86400*2, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'feed_sync': {'handler':handle_feed_sync, 'task_lease_id': 'feed_sync', 'taskType': 'handle_feed_sync', 'args': [], 'cycle_timer': 21600, 'min_cycle_timer': 3600, 'max_cycle_timer': 86400*14, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'service_watcher': {'handler':handle_service_watcher, 'task_lease_id': False, 'taskType': None, 'args': [], 'cycle_timer': 10, 'min_cycle_timer': 1, 'max_cycle_timer': 300, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'task_lease_id': False, 'taskType': None, 'args': [servicename], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
    'handle_metrics': {'handler': handle_metrics, 'task_lease_id': False, 'taskType': None, 'args': [], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
}

watcher_task_template = {
    'taskType': None,
    'watcher': None,
}
watcher_threads = {}

default_lease_ttl = 3600 # 1 hour ttl, should be more than enough in most cases


def watcher_func(*args, **kwargs):
    global system_user_auth

    while(True):
        logger.debug("starting generic watcher")
        all_ready = anchore_engine.clients.common.check_services_ready(['simplequeue'])
        if not all_ready:
            logger.info("simplequeue service not yet ready, will retry")
        else:
            try:
                logger.debug("attempting dequeue")
                qobj = simplequeue.dequeue(system_user_auth, 'watcher_tasks', max_wait_seconds=30)
                logger.debug("dequeue complete")

                if qobj:
                    logger.debug("got task from queue: " + str(qobj))
                    watcher = qobj['data']['watcher']
                    handler = watchers[watcher]['handler']
                    args = []
                    kwargs = {'mythread': watchers[watcher]}

                    lease_id = watchers[watcher]['task_lease_id']

                    # Old way
                    if not lease_id:
                        logger.debug('No task lease defined for watcher {}, initiating without lock protection'.format(watcher))
                        rc = handler(*args, **kwargs)
                    else:
                        rc = simplequeue.run_target_with_lease(system_user_auth, lease_id, handler, ttl=default_lease_ttl, *args, **kwargs)

                    mtimer = anchore_engine.subsys.metrics.get_summary_obj('anchore_monitor_runtime_seconds', function=watcher)
                    if mtimer:
                        with mtimer.labels(function=watcher).time():
                            rc = handler(*args, **kwargs)
                    else:
                        rc = handler(*args, **kwargs)
                else:
                    logger.debug("nothing in queue")
            except Exception as err:
                logger.warn("failed to process task this cycle: " + str(err))
        logger.debug("generic watcher done")
        time.sleep(5)

def monitor_func(**kwargs):
    global click, running, last_queued, system_user_auth, watchers, last_run
    
    if click < 5:
        click = click + 1
        logger.debug("Catalog monitor starting in: " + str(5 - click))
        return(True)

    if running or ((time.time() - last_run) < kwargs['kick_timer']):
        return(True)

    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        system_user_auth = localconfig['system_user_auth']

        for watcher in watchers.keys():
            if not watchers[watcher]['initialized']:
                # first time
                if 'cycle_timers' in kwargs and watcher in kwargs['cycle_timers']:
                    try:
                        the_cycle_timer = watchers[watcher]['cycle_timer']
                        min_cycle_timer = watchers[watcher]['min_cycle_timer']
                        max_cycle_timer = watchers[watcher]['max_cycle_timer']

                        config_cycle_timer = int(kwargs['cycle_timers'][watcher])
                        if config_cycle_timer < 0:
                            the_cycle_timer = abs(int(config_cycle_timer))
                        elif config_cycle_timer < min_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(watcher)+") is less than the allowed min ("+str(min_cycle_timer)+") - using allowed min")
                            the_cycle_timer = min_cycle_timer
                        elif config_cycle_timer > max_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(watcher)+") is greater than the allowed max ("+str(max_cycle_timer)+") - using allowed max")
                            the_cycle_timer = max_cycle_timer
                        else:
                            the_cycle_timer = config_cycle_timer

                        watchers[watcher]['cycle_timer'] = the_cycle_timer
                    except Exception as err:
                        logger.warn("exception setting custom cycle timer for handler ("+str(watcher)+") - using default")

                watchers[watcher]['initialized'] = True

            if watcher not in watcher_threads:
                if watchers[watcher]['taskType']:
                    # spin up a generic task watcher
                    logger.debug("starting generic task thread")
                    watcher_threads[watcher] = threading.Thread(target=watcher_func, args=[watcher], kwargs={})
                    watcher_threads[watcher].start()
                else:
                    # spin up a specific looping watcher thread
                    watcher_threads[watcher] = threading.Thread(target=watchers[watcher]['handler'], args=watchers[watcher]['args'], kwargs={'mythread': watchers[watcher]})
                    watcher_threads[watcher].start()

            all_ready = anchore_engine.clients.common.check_services_ready(['simplequeue'])
            if not all_ready:
                logger.info("simplequeue service not yet ready, will retry")
            elif time.time() - watchers[watcher]['last_queued'] > watchers[watcher]['cycle_timer']:
                if watchers[watcher]['taskType']:
                    logger.debug("should queue job: " + watcher)
                    watcher_task = copy.deepcopy(watcher_task_template)
                    watcher_task['watcher'] = watcher
                    watcher_task['taskType'] = watchers[watcher]['taskType']
                    try:
                        if not simplequeue.is_inqueue(system_user_auth, 'watcher_tasks', watcher_task):
                            qobj = simplequeue.enqueue(system_user_auth, 'watcher_tasks', watcher_task)
                            logger.debug(str(watcher_task)+": init task queued: " + str(qobj))
                        else:
                            logger.debug(str(watcher_task)+": init task already queued")

                        watchers[watcher]['last_queued'] = time.time()
                    except Exception as err:
                        logger.warn("failed to enqueue watcher task: " + str(err))

    except Exception as err:
        logger.error(str(err))
    finally:
        logger.debug("FIRING DONE: catalog_monitor")
        running = False
        last_run = time.time()

    logger.debug("exiting monitor thread")

monitor_thread = None
def monitor(**kwargs):
    global monitor_thread
    try:
        donew = False
        if monitor_thread:
            if monitor_thread.isAlive():
                logger.spew("MON: thread still running")
            else:
                logger.spew("MON: thread stopped running")
                donew = True
                monitor_thread.join()
                logger.spew("MON: thread joined: isAlive=" + str(monitor_thread.isAlive()))
        else:
            logger.spew("MON: no thread")
            donew = True

        if donew:
            logger.spew("MON: starting")
            monitor_thread = threading.Thread(target=monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))


