import copy
import os
import re
import threading
import time
import uuid
import traceback

import connexion
from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource

# anchore modules
from anchore_engine.clients import catalog, localanchore, simplequeue, localanchore_standalone
import anchore_engine.configuration.localconfig
import anchore_engine.services.common
import anchore_engine.subsys.taskstate
import anchore_engine.subsys.notifications
from anchore_engine.subsys import logger

import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    application.app.url_map.strict_slashes = False
    application.add_api('swagger.yaml')
    app = application
except Exception as err:
    traceback.print_exc()
    raise err


# service funcs (must be here)
def createService(sname, config):
    global app

    try:
        myconfig = config['services'][sname]
    except Exception as err:
        raise err

    try:
        kick_timer = int(myconfig['cycle_timer_seconds'])
    except:
        kick_timer = 1

    doapi = False
    try:
        if myconfig['listen'] and myconfig['port'] and myconfig['endpoint_hostname']:
            doapi = True
    except:
        doapi = False

    if doapi:
        # start up flask service

        flask_site = WSGIResource(reactor, reactor.getThreadPool(), app)
        root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
        ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

        # start up the monitor as a looping call
        kwargs = {'kick_timer': kick_timer}
        lc = LoopingCall(anchore_engine.services.analyzer.monitor, **kwargs)
        lc.start(1)
    else:
        # start up the monitor as a timer service
        kwargs = {'kick_timer': kick_timer}
        svc = internet.TimerService(1, anchore_engine.services.analyzer.monitor, **kwargs)
        svc.setName(sname)
        ret_svc = svc

    return (ret_svc)

def initializeService(sname, config):
    return (anchore_engine.services.common.initializeService(sname, config))

def registerService(sname, config):
    return (anchore_engine.services.common.registerService(sname, config, enforce_unique=False))


############################################

queuename = "images_to_analyze"
click = 0
running = False
last_run = 0
system_user_auth = ('anchore-system', '')
current_avg = 0.0
current_avg_count = 0.0

def perform_analyze(userId, manifest, image_record, registry_creds, layer_cache_enable=False):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    try:
        myconfig = localconfig['services']['analyzer']
    except:
        myconfig = {}

    driver = 'localanchore'
    if 'analyzer_driver' in myconfig:
        driver = myconfig['analyzer_driver']

    if driver == 'nodocker':
        return(perform_analyze_nodocker(userId, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable))
    else:
        return(perform_analyze_localanchore(userId, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable))

def perform_analyze_nodocker(userId, manifest, image_record, registry_creds, layer_cache_enable=False):
    ret_analyze = {}
    ret_query = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    try:
        tmpdir = localconfig['tmp_dir']
    except Exception as err:
        logger.warn("could not get tmp_dir from localconfig - exception: " + str(err))
        tmpdir = "/tmp"

    use_cache_dir=None
    if layer_cache_enable:
        use_cache_dir = os.path.join(tmpdir, "anchore_layercache")

    # choose the first TODO possible more complex selection here
    try:
        image_detail = image_record['image_detail'][0]
        registry_manifest = manifest
        pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['imageDigest']
        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        logger.debug("using pullstring ("+str(pullstring)+") and fulltag ("+str(fulltag)+") to pull image data")
    except Exception as err:
        image_detail = pullstring = fulltag = None
        raise Exception("failed to extract requisite information from image_record - exception: " + str(err))
        
    timer = int(time.time())
    logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))
    logger.info("performing analysis on image: " + str([userId, pullstring, fulltag]))

    logger.debug("obtaining anchorelock..." + str(pullstring))
    with localanchore.get_anchorelock(lockId=pullstring):
        logger.debug("obtaining anchorelock successful: " + str(pullstring))
        analyzed_image_report = localanchore_standalone.analyze_image(userId, registry_manifest, image_record, tmpdir, registry_creds=registry_creds, use_cache_dir=use_cache_dir)
        ret_analyze = analyzed_image_report

    logger.info("performing analysis on image complete: " + str(pullstring))

    return (ret_analyze)

def perform_analyze_localanchore(userId, manifest, image_record, registry_creds, layer_cache_enable=False):
    ret_analyze = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    do_docker_cleanup = localconfig['cleanup_images']

    try:
        image_detail = image_record['image_detail'][0]
        registry_manifest = manifest
        pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['imageDigest']
        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        logger.debug("using pullstring ("+str(pullstring)+") and fulltag ("+str(fulltag)+") to pull image data")
    except Exception as err:
        image_detail = pullstring = fulltag = None
        raise Exception("failed to extract requisite information from image_record - exception: " + str(err))


    timer = int(time.time())
    logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))
    logger.debug("obtaining anchorelock..." + str(pullstring))
    with localanchore.get_anchorelock(lockId=pullstring):
        logger.debug("obtaining anchorelock successful: " + str(pullstring))

        logger.spew("TIMING MARK1: " + str(int(time.time()) - timer))
        logger.info("performing analysis on image: " + str(pullstring))

        # pull the digest, but also any tags associated with the image (that we know of) in order to populate the local docker image
        try:
            rc = localanchore.pull(userId, pullstring, image_detail, pulltags=True,
                                                          registry_creds=registry_creds)
            if not rc:
                raise Exception("anchore analyze failed:")
            pullstring = re.sub("sha256:", "", rc['Id'])
            image_detail['imageId'] = pullstring
        except Exception as err:
            logger.error("error on pull: " + str(err))
            raise err

        logger.spew("TIMING MARK2: " + str(int(time.time()) - timer))

        # analyze!
        try:
            rc = localanchore.analyze(pullstring, image_detail)
            if not rc:
                raise Exception("anchore analyze failed:")
        except Exception as err:
            logger.error("error on analyze: " + str(err))
            raise err

        logger.spew("TIMING MARK3: " + str(int(time.time()) - timer))

        # get the result from anchore
        logger.debug("retrieving image data from anchore")
        try:
            image_data = localanchore.get_image_export(pullstring, image_detail)
            if not image_data:
                raise Exception("anchore image data export failed:")
        except Exception as err:
            logger.error("error on image export: " + str(err))
            raise err

        logger.spew("TIMING MARK5: " + str(int(time.time()) - timer))

        try:
            logger.debug("removing image: " + str(pullstring))
            rc = localanchore.remove_image(pullstring, docker_remove=do_docker_cleanup,
                                                                  anchore_remove=True)
            logger.debug("removing image complete: " + str(pullstring))
        except Exception as err:
            raise err

        logger.spew("TIMING MARK6: " + str(int(time.time()) - timer))

    ret_analyze = image_data

    logger.info("performing analysis on image complete: " + str(pullstring))
    return (ret_analyze)


def process_analyzer_job(system_user_auth, qobj, layer_cache_enable):
    global current_avg, current_avg_count

    timer = int(time.time())
    try:
        record = qobj['data']
        userId = record['userId']
        image_record = record['image_record']
        manifest = record['manifest']

        imageDigest = image_record['imageDigest']
        user_record = catalog.get_user(system_user_auth, userId)
        user_auth = (user_record['userId'], user_record['password'])

        # check to make sure image is still in DB
        try:
            image_records = catalog.get_image(user_auth, imageDigest=imageDigest)
            if image_records:
                image_record = image_records[0]
            else:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.warn("dequeued image cannot be fetched from catalog - skipping analysis (" + str(
                imageDigest) + ") - exception: " + str(err))
            return (True)

        logger.info("image dequeued for analysis: " + str(userId) + " : " + str(imageDigest))

        try:
            logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))

            last_analysis_status = image_record['analysis_status']
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.working_state('analyze')
            rc = catalog.update_image(user_auth, imageDigest, image_record)

            # disable the webhook call for image state transistion to 'analyzing'
            #try:
            #    for image_detail in image_record['image_detail']:
            #        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
            #        npayload = {
            #            'last_eval': {'imageDigest': imageDigest, 'analysis_status': last_analysis_status},
            #            'curr_eval': {'imageDigest': imageDigest, 'analysis_status': image_record['analysis_status']},
            #        }
            #        rc = anchore_engine.subsys.notifications.queue_notification(userId, fulltag, 'analysis_update', npayload)
            #except Exception as err:
            #    logger.warn("failed to enqueue notification on image analysis state update - exception: " + str(err))

            # actually do analysis
            registry_creds = catalog.get_registry(user_auth)
            image_data = perform_analyze(userId, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable)

            imageId = None
            try:
                imageId = image_data[0]['image']['imageId']
            except Exception as err:
                logger.warn("could not get imageId after analysis or from image record - exception: " + str(err))

            logger.debug("archiving analysis data")
            rc = catalog.put_document(user_auth, 'analysis_data', imageDigest, image_data)

            if rc:
                try:
                    logger.debug("extracting image content data")
                    image_content_data = {}
                    for content_type in anchore_engine.services.common.image_content_types:
                        try:
                            image_content_data[content_type] = anchore_engine.services.common.extract_analyzer_content(image_data, content_type)
                        except:
                            image_content_data[content_type] = {}

                    if image_content_data:
                        logger.debug("adding image content data to archive")
                        rc = catalog.put_document(user_auth, 'image_content_data', imageDigest, image_content_data)

                    try:
                        logger.debug("adding image analysis data to image_record")
                        anchore_engine.services.common.update_image_record_with_analysis_data(image_record, image_data)

                    except Exception as err:
                        raise err

                except Exception as err:
                    logger.warn("could not store image content metadata to archive - exception: " + str(err))

                logger.debug("adding image record to policy-engine service (" + str(userId) + " : " + str(imageId) + ")")
                try:
                    if not imageId:
                        raise Exception("cannot add image to policy engine without an imageId")

                    localconfig = anchore_engine.configuration.localconfig.get_config()
                    verify = localconfig['internal_ssl_verify']

                    client = anchore_engine.clients.policy_engine.get_client(user=system_user_auth[0], password=system_user_auth[1], verify_ssl=verify)

                    try:
                        logger.debug("clearing any existing record in policy engine for image: " + str(imageId))
                        rc = client.delete_image(user_id=userId, image_id=imageId)
                    except Exception as err:
                        logger.warn("exception on pre-delete - exception: " + str(err))

                    request = ImageIngressRequest()
                    request.user_id = userId
                    request.image_id = imageId
                    request.fetch_url='catalog://'+str(userId)+'/analysis_data/'+str(imageDigest)
                    logger.debug("policy engine request: " + str(request))
                    resp = client.ingress_image(request)
                    logger.debug("policy engine image add response: " + str(resp))

                    try:
                        # force a fresh CVE scan
                        resp = client.get_image_vulnerabilities(user_id=userId, image_id=imageId, force_refresh=True)
                    except Exception as err:
                        logger.warn("post analysis CVE scan failed for image: " + str(imageId))

                except Exception as err:
                    raise Exception("adding image to policy-engine failed - exception: " + str(err))

                logger.debug("updating image catalog record analysis_status")
                
                last_analysis_status = image_record['analysis_status']
                image_record['analysis_status'] = anchore_engine.subsys.taskstate.complete_state('analyze')
                rc = catalog.update_image(user_auth, imageDigest, image_record)

                try:
                    for image_detail in image_record['image_detail']:
                        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                        npayload = {
                            'last_eval': {'imageDigest': imageDigest, 'analysis_status': last_analysis_status},
                            'curr_eval': {'imageDigest': imageDigest, 'analysis_status': image_record['analysis_status']},
                        }
                        rc = anchore_engine.subsys.notifications.queue_notification(userId, fulltag, 'analysis_update', npayload)
                except Exception as err:
                    logger.warn("failed to enqueue notification on image analysis state update - exception: " + str(err))

            else:
                raise Exception("analysis archive failed to store")

            logger.info("analysis complete: " + str(userId) + " : " + str(imageDigest))

            logger.spew("TIMING MARK1: " + str(int(time.time()) - timer))

            try:
                run_time = float(time.time() - timer)
                current_avg_count = current_avg_count + 1.0
                new_avg = current_avg + ((run_time - current_avg) / current_avg_count)
                current_avg = new_avg
            except:
                pass

        except Exception as err:
            logger.exception("problem analyzing image - exception: " + str(err))
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.fault_state('analyze')
            image_record['image_status'] = anchore_engine.subsys.taskstate.fault_state('image_status')
            rc = catalog.update_image(user_auth, imageDigest, image_record)

    except Exception as err:
        logger.warn("job processing bailed - exception: " + str(err))
        raise err

    return (True)

def monitor_func(**kwargs):
    global click, running, last_run, queuename, system_user_auth

    timer = int(time.time())
    if click < 5:
        click = click + 1
        logger.debug("Analyzer starting in: " + str(5 - click))
        return (True)

    if round(time.time() - last_run) < kwargs['kick_timer']:
        logger.spew(
            "timer hasn't kicked yet: " + str(round(time.time() - last_run)) + " : " + str(kwargs['kick_timer']))
        return (True)

    try:
        running = True
        last_run = time.time()
        logger.debug("FIRING: analyzer")

        localconfig = anchore_engine.configuration.localconfig.get_config()
        system_user_auth = localconfig['system_user_auth']

        if True:
            try:

                myconfig = localconfig['services']['analyzer']
                max_analyze_threads = int(myconfig.get('max_threads', 1))
                layer_cache_enable = myconfig.get('layer_cache_enable', False)
                #try:
                #    max_analyze_threads = int(myconfig['max_threads'])
                #except:
                #    max_analyze_threads = 1

                logger.debug("max threads: " + str(max_analyze_threads))
                threads = []
                for i in range(0, max_analyze_threads):
                    qobj = simplequeue.dequeue(system_user_auth, queuename)
                    #if simplequeue.qlen(system_user_auth, queuename) > 0:                    
                    if qobj:
                        myqobj = copy.deepcopy(qobj)
                        logger.spew("incoming queue object: " + str(myqobj))
                        logger.debug("incoming queue task: " + str(myqobj.keys()))
                        logger.debug("starting thread")
                        athread = threading.Thread(target=process_analyzer_job, args=(system_user_auth, myqobj,layer_cache_enable))
                        athread.start()
                        threads.append(athread)
                        logger.debug("thread started")
                    else:
                        logger.debug("analyzer queue is empty - no work this cycle")

                for athread in threads:
                    logger.debug("joining thread")
                    athread.join()
                    logger.debug("thread joined")

                # TODO - perform cache maint here, no analyzer threads running
                
            except Exception as err:
                logger.error(str(err))
    except Exception as err:
        logger.error(str(err))
    finally:
        running = False
        logger.debug("FIRING DONE: analyzer: " + str(int(time.time()) - timer))

    return (True)


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
                logger.spew("MON: thread joined: " + str(monitor_thread.isAlive()))
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
