import copy
import os
import threading
import time
import json
import operator
import pkg_resources

# anchore modules
import anchore_engine.clients.localanchore_standalone
import anchore_engine.common.helpers
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.clients import localanchore_standalone
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
import anchore_engine.common
import anchore_engine.subsys.taskstate
import anchore_engine.subsys.notifications
from anchore_engine.subsys import logger

from anchore_engine.utils import AnchoreException
import anchore_engine.subsys.events as events
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.service import ApiService
from anchore_engine.db import session_scope

############################################

queuename = "images_to_analyze"
system_user_auth = ('anchore-system', '')
#current_avg = 0.0
#current_avg_count = 0.0


def perform_analyze(userId, manifest, image_record, registry_creds, layer_cache_enable=False):

    return perform_analyze_nodocker(userId, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable)

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
    with anchore_engine.clients.localanchore_standalone.get_anchorelock(lockId=pullstring, driver='nodocker'):
        logger.debug("obtaining anchorelock successful: " + str(pullstring))
        analyzed_image_report = localanchore_standalone.analyze_image(userId, registry_manifest, image_record, tmpdir, localconfig, registry_creds=registry_creds, use_cache_dir=use_cache_dir)
        ret_analyze = analyzed_image_report

    logger.info("performing analysis on image complete: " + str(pullstring))

    return (ret_analyze)


def process_analyzer_job(system_user_auth, qobj, layer_cache_enable):
    global servicename #current_avg, current_avg_count

    timer = int(time.time())
    event = None
    try:
        logger.debug('dequeued object: {}'.format(qobj))

        record = qobj['data']
        userId = record['userId']
        imageDigest = record['imageDigest']
        manifest = record['manifest']

        # check to make sure image is still in DB
        catalog_client = internal_client_for(CatalogClient, userId)
        try:
            image_records = catalog_client.get_image(imageDigest=imageDigest)
            if image_records:
                image_record = image_records[0]
            else:
                raise Exception("empty image record from catalog")
        except Exception as err:
            logger.warn("dequeued image cannot be fetched from catalog - skipping analysis (" + str(imageDigest) + ") - exception: " + str(err))
            return (True)

        logger.info("image dequeued for analysis: " + str(userId) + " : " + str(imageDigest))
        if image_record['analysis_status'] != anchore_engine.subsys.taskstate.base_state('analyze'):
            logger.debug("dequeued image is not in base state - skipping analysis")
            return(True)
        
        try:
            logger.spew("TIMING MARK0: " + str(int(time.time()) - timer))

            last_analysis_status = image_record['analysis_status']
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.working_state('analyze')
            rc = catalog_client.update_image(imageDigest, image_record)

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
            registry_creds = catalog_client.get_registry()
            try:
                image_data = perform_analyze(userId, manifest, image_record, registry_creds, layer_cache_enable=layer_cache_enable)
            except AnchoreException as e:
                event = events.AnalyzeImageFail(user_id=userId, image_digest=imageDigest, error=e.to_dict())
                raise

            imageId = None
            try:
                imageId = image_data[0]['image']['imageId']
            except Exception as err:
                logger.warn("could not get imageId after analysis or from image record - exception: " + str(err))

            try:
                logger.debug("archiving analysis data")
                rc = catalog_client.put_document('analysis_data', imageDigest, image_data)
            except Exception as e:
                err = CatalogClientError(msg='Failed to upload analysis data to catalog', cause=e)
                event = events.ArchiveAnalysisFail(user_id=userId, image_digest=imageDigest, error=err.to_dict())
                raise err

            if rc:
                try:
                    logger.debug("extracting image content data")
                    image_content_data = {}
                    for content_type in anchore_engine.common.image_content_types + anchore_engine.common.image_metadata_types:
                        try:
                            image_content_data[content_type] = anchore_engine.common.helpers.extract_analyzer_content(image_data, content_type, manifest=manifest)
                        except:
                            image_content_data[content_type] = {}

                    if image_content_data:
                        logger.debug("adding image content data to archive")
                        rc = catalog_client.put_document('image_content_data', imageDigest, image_content_data)

                    try:
                        logger.debug("adding image analysis data to image_record")
                        anchore_engine.common.helpers.update_image_record_with_analysis_data(image_record, image_data)

                    except Exception as err:
                        raise err

                except Exception as err:
                    import traceback
                    traceback.print_exc()
                    logger.warn("could not store image content metadata to archive - exception: " + str(err))

                logger.debug("adding image record to policy-engine service (" + str(userId) + " : " + str(imageId) + ")")
                try:
                    if not imageId:
                        raise Exception("cannot add image to policy engine without an imageId")

                    localconfig = anchore_engine.configuration.localconfig.get_config()
                    verify = localconfig['internal_ssl_verify']

                    pe_client = internal_client_for(PolicyEngineClient, userId)

                    try:
                        logger.debug("clearing any existing record in policy engine for image: " + str(imageId))
                        rc = pe_client.delete_image(user_id=userId, image_id=imageId)
                    except Exception as err:
                        logger.warn("exception on pre-delete - exception: " + str(err))

                    logger.info('Loading image into policy engine: {} {}'.format(userId, imageId))
                    image_analysis_fetch_url='catalog://'+str(userId)+'/analysis_data/'+str(imageDigest)
                    logger.debug("policy engine request: " + image_analysis_fetch_url)
                    resp = pe_client.ingress_image(userId, imageId, image_analysis_fetch_url)
                    logger.debug("policy engine image add response: " + str(resp))

                except Exception as err:
                    newerr = PolicyEngineClientError(msg='Adding image to policy-engine failed', cause=str(err))
                    event = events.LoadAnalysisFail(user_id=userId, image_digest=imageDigest, error=newerr.to_dict())
                    raise newerr

                logger.debug("updating image catalog record analysis_status")
                
                last_analysis_status = image_record['analysis_status']
                image_record['analysis_status'] = anchore_engine.subsys.taskstate.complete_state('analyze')
                image_record['analyzed_at'] = int(time.time())
                rc = catalog_client.update_image(imageDigest, image_record)

                try:
                    annotations = {}
                    try:
                        if image_record.get('annotations', '{}'):
                            annotations = json.loads(image_record.get('annotations', '{}'))
                    except Exception as err:
                        logger.warn("could not marshal annotations from json - exception: " + str(err))

                    for image_detail in image_record['image_detail']:
                        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                        last_payload = {'imageDigest': imageDigest, 'analysis_status': last_analysis_status, 'annotations': annotations}
                        curr_payload = {'imageDigest': imageDigest, 'analysis_status': image_record['analysis_status'], 'annotations': annotations}
                        npayload = {
                            'last_eval': last_payload,
                            'curr_eval': curr_payload,
                        }
                        if annotations:
                            npayload['annotations'] = annotations

                        rc = anchore_engine.subsys.notifications.queue_notification(userId, fulltag, 'analysis_update', npayload)
                except Exception as err:
                    logger.warn("failed to enqueue notification on image analysis state update - exception: " + str(err))

            else:
                err = CatalogClientError(msg='Failed to upload analysis data to catalog', cause='Invalid response from catalog API - {}'.format(str(rc)))
                event = events.ArchiveAnalysisFail(user_id=userId, image_digest=imageDigest, error=err.to_dict())
                raise err

            logger.info("analysis complete: " + str(userId) + " : " + str(imageDigest))

            logger.spew("TIMING MARK1: " + str(int(time.time()) - timer))

            try:
                run_time = float(time.time() - timer)
                #current_avg_count = current_avg_count + 1.0
                #new_avg = current_avg + ((run_time - current_avg) / current_avg_count)
                #current_avg = new_avg

                anchore_engine.subsys.metrics.histogram_observe('anchore_analysis_time_seconds', run_time, buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0], status="success")
                #anchore_engine.subsys.metrics.counter_inc('anchore_images_analyzed_total')

                #localconfig = anchore_engine.configuration.localconfig.get_config()
                #service_record = {'hostid': localconfig['host_id'], 'servicename': servicename}
                #anchore_engine.subsys.servicestatus.set_status(service_record, up=True, available=True, detail={'avg_analysis_time_sec': current_avg, 'total_analysis_count': current_avg_count}, update_db=True)

            except Exception as err:
                logger.warn(str(err))
                pass

        except Exception as err:
            run_time = float(time.time() - timer)
            logger.exception("problem analyzing image - exception: " + str(err))
            anchore_engine.subsys.metrics.histogram_observe('anchore_analysis_time_seconds', run_time, buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0], status="fail")
            image_record['analysis_status'] = anchore_engine.subsys.taskstate.fault_state('analyze')
            image_record['image_status'] = anchore_engine.subsys.taskstate.fault_state('image_status')
            rc = catalog_client.update_image(imageDigest, image_record)
        finally:
            if event:
                try:
                    catalog_client.add_event(event)
                except:
                    logger.error('Ignoring error creating analysis failure event')


    except Exception as err:
        logger.warn("job processing bailed - exception: " + str(err))
        raise err

    return (True)

# TODO should probably be defined in and raised by the clients
class CatalogClientError(AnchoreException):
    def __init__(self, cause, msg='Failed to execute out catalog API'):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)

    def __str__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)


class PolicyEngineClientError(AnchoreException):
    def __init__(self, cause, msg='Failed to execute out policy engine API'):
        self.cause = str(cause)
        self.msg = msg

    def __repr__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)

    def __str__(self):
        return '{} - exception: {}'.format(self.msg, self.cause)


def handle_layer_cache(**kwargs):
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        myconfig = localconfig['services']['analyzer']

        cachemax_gbs = int(myconfig.get('layer_cache_max_gigabytes', 1))
        cachemax = cachemax_gbs * 1000000000

        try:
            tmpdir = localconfig['tmp_dir']
        except Exception as err:
            logger.warn("could not get tmp_dir from localconfig - exception: " + str(err))
            tmpdir = "/tmp"
        use_cache_dir = os.path.join(tmpdir, "anchore_layercache")
        if os.path.exists(use_cache_dir):
            totalsize = 0
            layertimes = {}
            layersizes = {}
            try:
                for f in os.listdir(os.path.join(use_cache_dir, 'sha256')):
                    layerfile = os.path.join(use_cache_dir, 'sha256', f)
                    layerstat = os.stat(layerfile)
                    totalsize = totalsize + layerstat.st_size
                    layersizes[layerfile] = layerstat.st_size
                    layertimes[layerfile] = max([layerstat.st_mtime, layerstat.st_ctime, layerstat.st_atime])
                    
                if totalsize > cachemax:
                    logger.debug("layer cache total size ("+str(totalsize)+") exceeds configured cache max ("+str(cachemax)+") - performing cleanup")
                    currsize = totalsize
                    sorted_layers = sorted(list(layertimes.items()), key=operator.itemgetter(1))
                    while(currsize > cachemax):
                        rmlayer = sorted_layers.pop(0)
                        logger.debug("removing cached layer: " + str(rmlayer))
                        os.remove(rmlayer[0])
                        currsize = currsize - layersizes[rmlayer[0]]
                        logger.debug("currsize after remove: " + str(currsize))

            except Exception as err:
                raise(err)
        
    except Exception as err:
        raise(err)

    return(True)

def handle_image_analyzer(*args, **kwargs):
    """
    Processor for image analysis requests coming from the work queue

    :param args:
    :param kwargs:
    :return:
    """
    global system_user_auth, queuename, servicename

    cycle_timer = kwargs['mythread']['cycle_timer']

    localconfig = anchore_engine.configuration.localconfig.get_config()
    system_user_auth = localconfig['system_user_auth']

    threads = []
    layer_cache_dirty = True
    while(True):
        logger.debug("analyzer thread cycle start")
        try:
            myconfig = localconfig['services']['analyzer']
            max_analyze_threads = int(myconfig.get('max_threads', 1))
            layer_cache_enable = myconfig.get('layer_cache_enable', False)

            logger.debug("max threads: " + str(max_analyze_threads))
            q_client = internal_client_for(SimpleQueueClient, userId=None)

            if len(threads) < max_analyze_threads:
                logger.debug("analyzer has free worker threads {} / {}".format(len(threads), max_analyze_threads))
                qobj = q_client.dequeue(queuename)
                if qobj:
                    logger.debug("got work from queue task Id: {}".format(qobj.get('queueId', 'unknown')))
                    myqobj = copy.deepcopy(qobj)
                    logger.spew("incoming queue object: " + str(myqobj))
                    logger.debug("incoming queue task: " + str(list(myqobj.keys())))
                    logger.debug("starting thread")
                    athread = threading.Thread(target=process_analyzer_job, args=(system_user_auth, myqobj,layer_cache_enable))
                    athread.start()
                    threads.append(athread)
                    logger.debug("thread started")
                    layer_cache_dirty = True
                else:
                    logger.debug("analyzer queue is empty - no work this cycle")
            else:
                logger.debug("all workers are busy")

            alive_threads = []
            while(threads):
                athread = threads.pop()
                if not athread.isAlive():
                    try:
                        logger.debug("thread completed - joining")
                        athread.join()
                        logger.debug("thread joined")
                    except Exception as err:
                        logger.warn("cannot join thread - exception: " + str(err))
                else:
                    alive_threads.append(athread)
            threads = alive_threads

            if layer_cache_enable and layer_cache_dirty and len(threads) == 0:
                logger.debug("running layer cache handler")
                try:
                    handle_layer_cache()
                    layer_cache_dirty = False
                except Exception as err:
                    logger.warn("layer cache management failed - exception: " + str(err))

        except Exception as err:
            logger.exception('Failure in image analysis loop')

        logger.debug("analyzer thread cycle complete: next in "+str(cycle_timer))
        time.sleep(cycle_timer)
    return(True)

def handle_metrics(*args, **kwargs):

    cycle_timer = kwargs['mythread']['cycle_timer']

    while(True):
        try:
            localconfig = anchore_engine.configuration.localconfig.get_config()
            try:
                tmpdir = localconfig['tmp_dir']
                svfs = os.statvfs(tmpdir)
                available_bytes = svfs.f_bsize * svfs.f_bavail
                anchore_engine.subsys.metrics.gauge_set("anchore_tmpspace_available_bytes", available_bytes)
            except Exception as err:
                logger.warn("unable to detect available bytes probe - exception: " + str(err))
        except Exception as err:
            logger.warn("handler failed - exception: " + str(err))

        time.sleep(cycle_timer)

    return(True)

# monitor infrastructure

# monitors = {
#     'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [AnalyzerService.__service_name__], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
#     'image_analyzer': {'handler': handle_image_analyzer, 'taskType': 'handle_image_analyzer', 'args': [], 'cycle_timer': 1, 'min_cycle_timer': 1, 'max_cycle_timer': 120, 'last_queued': 0, 'last_return': False, 'initialized': False},
#     'handle_metrics': {'handler': handle_metrics, 'taskType': 'handle_metrics', 'args': [servicename], 'cycle_timer': 15, 'min_cycle_timer': 15, 'max_cycle_timer': 15, 'last_queued': 0, 'last_return': False, 'initialized': False},
# }
# monitor_threads = {}


class AnalyzerService(ApiService):
    __service_name__ = 'analyzer'
    __spec_dir__ = pkg_resources.resource_filename(__name__, 'swagger')
    __service_api_version__ = 'v1'
    __monitors__ = {
        'service_heartbeat': {'handler': anchore_engine.subsys.servicestatus.handle_service_heartbeat, 'taskType': 'handle_service_heartbeat', 'args': [__service_name__], 'cycle_timer': 60, 'min_cycle_timer': 60, 'max_cycle_timer': 60, 'last_queued': 0, 'last_return': False, 'initialized': False},
        'image_analyzer': {'handler': handle_image_analyzer, 'taskType': 'handle_image_analyzer', 'args': [], 'cycle_timer': 5, 'min_cycle_timer': 1, 'max_cycle_timer': 120, 'last_queued': 0, 'last_return': False, 'initialized': False},
        'handle_metrics': {'handler': handle_metrics, 'taskType': 'handle_metrics', 'args': [__service_name__], 'cycle_timer': 15, 'min_cycle_timer': 15, 'max_cycle_timer': 15, 'last_queued': 0, 'last_return': False, 'initialized': False},
    }
