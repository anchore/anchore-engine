import copy
import re
import threading
import time
import traceback

import connexion
from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource

# anchore modules
from anchore_engine.clients import catalog, localanchore, simplequeue
import anchore_engine.configuration.localconfig
import anchore_engine.services.common
import anchore_engine.subsys.taskstate
from anchore_engine.subsys import logger

import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
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


def perform_analyze(userId, pullstring, fulltag, image_detail, registry_creds):
    ret_analyze = {}
    ret_query = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    do_docker_cleanup = localconfig['cleanup_images']

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

        # query!
        try:
            query_data = localanchore.run_queries(pullstring, image_detail)
            if not rc:
                raise Exception("anchore queries failed:")
        except Exception as err:
            logger.error("error on run_queries: " + str(err))
            raise err

        logger.spew("TIMING MARK4: " + str(int(time.time()) - timer))

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
    ret_query = query_data
    logger.info("performing analysis on image complete: " + str(pullstring))
    return (ret_analyze, ret_query)


def process_analyzer_job(system_user_auth, qobj):
    global current_avg, current_avg_count

    timer = int(time.time())
    try:
        record = qobj['data']
        userId = record['userId']
        image_record = record['image_record']
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
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.working_state('analyze')
            rc = catalog.update_image(user_auth, imageDigest, image_record)

            # actually do analysis

            # for pullstring in pullstrings.keys():
            for image_detail in image_record['image_detail']:
                pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['digest']
                fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']

                imageId = None
                if 'imageId' in image_detail and image_detail['imageId']:
                    imageId = image_detail['imageId']

                logger.info("analysis starting: " + str(userId) + " : " + str(imageDigest) + " : " + str(fulltag) + " : " + str(imageId))

                logger.spew("TIMING MARKX: " + str(int(time.time()) - timer))

                registry_creds = catalog.get_registry(user_auth)

                image_data, query_data = perform_analyze(userId, pullstring, fulltag, image_detail, registry_creds)
                logger.spew("TIMING MARKY: " + str(int(time.time()) - timer))

                logger.debug("archiving query data")
                rc = catalog.put_document(user_auth, 'query_data', imageDigest, query_data)
                if rc:
                    logger.debug("storing image query data to catalog")
                else:
                    raise Exception("query archive failed to store")

                if not imageId:
                    try:
                        imageId = image_data[0]['image']['imageId']
                    except Exception as err:
                        logger.warn("could not get imageId after analysis or from image record - exception: " + str(err))

                logger.debug("archiving analysis data")
                resource_url = catalog.put_document(user_auth, 'analysis_data', imageDigest, image_data)
                if resource_url:

                    logger.debug("adding image record to policy-engine service (" + str(userId) + " : " + str(imageId) + ")")
                    try:
                        if not imageId:
                            raise Exception("cannot add image to policy engine without an imageId")

                        localconfig = anchore_engine.configuration.localconfig.get_config()
                        verify = localconfig['internal_ssl_verify']
                    
                        client = anchore_engine.clients.policy_engine.get_client(user=system_user_auth[0], password=system_user_auth[1], verify_ssl=verify)
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
                    image_record['analysis_status'] = anchore_engine.subsys.taskstate.complete_state('analyze')
                    rc = catalog.update_image(user_auth, imageDigest, image_record)
                else:
                    raise Exception("analysis archive failed to store")

                logger.info("analysis complete: " + str(userId) + " : " + str(imageDigest) + " : " + str(fulltag))
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

        queues = simplequeue.get_queues(system_user_auth)
        if not queues:
            logger.warn("could not get any queues from simplequeue client, cannot do any work")
        elif queuename not in queues:
            logger.error("connected to simplequeue, but could not find queue (" + queuename + "), cannot do any work")
        else:
            try:

                try:
                    myconfig = localconfig['services']['analyzer']
                    max_analyze_threads = int(myconfig['max_threads'])
                except:
                    max_analyze_threads = 1

                logger.debug("max threads: " + str(max_analyze_threads))
                threads = []
                for i in range(0, max_analyze_threads):
                    if simplequeue.qlen(system_user_auth, queuename) > 0:
                        qobj = simplequeue.dequeue(system_user_auth, queuename)
                        if qobj:
                            myqobj = copy.deepcopy(qobj)
                            logger.debug("incoming queue object: " + str(myqobj))
                            logger.debug("THR: starting thread")
                            athread = threading.Thread(target=process_analyzer_job, args=(system_user_auth, myqobj,))
                            athread.start()
                            threads.append(athread)
                            logger.debug("THR: thread started")

                            # rc = process_analyzer_job(system_user_auth, myqobj)

                    else:
                        logger.debug("analyzer queue is empty - no work this cycle")

                for athread in threads:
                    logger.debug("THR: joining thread")
                    athread.join()
                    logger.debug("THR: thread joined")

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
