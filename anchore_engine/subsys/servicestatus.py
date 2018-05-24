import json 
import time

from anchore_engine.db import db_services, session_scope
from anchore_engine.subsys import logger
import anchore_engine.subsys.metrics
import anchore_engine.configuration.localconfig
import anchore_engine.version

service_statuses = {}
my_service_record = None

def get_my_service_record():
    global my_service_record
    return(my_service_record)

def set_my_service_record(service_record):
    global my_service_record
    my_service_record = service_record
    return(True)

def set_status(service_record, up=True, available=True, busy=False, message="all good", detail=None, update_db=False):
    global service_statuses
    hostid = service_record['hostid']
    servicename = service_record['servicename']
    base_url = service_record.get('base_url', 'N/A')
    service = '__'.join([hostid, servicename, base_url])

    if service not in service_statuses:
        service_statuses[service] = {}

    code_version = anchore_engine.version.version
    db_version = anchore_engine.version.db_version

    service_statuses[service]['up']= up
    service_statuses[service]['available'] = available
    service_statuses[service]['busy'] = busy 
    service_statuses[service]['message'] = message
    service_statuses[service]['detail'] = detail if detail is not None else {}
    service_statuses[service]['version'] = code_version
    service_statuses[service]['db_version'] = db_version

    if update_db:
        update_status(service_record)

def update_status(service_record):
    global service_statuses, my_service_record
    hostid = service_record['hostid']
    servicename = service_record['servicename']
    base_url = service_record.get('base_url', 'N/A')
    service = '__'.join([hostid, servicename, base_url])

    with session_scope() as dbsession:
        db_service_record = db_services.get(hostid, servicename, base_url, session=dbsession)
        logger.debug("db service record: {}".format(db_service_record))
        if db_service_record:
            my_service_record = db_service_record
            my_service_record['heartbeat'] = time.time()

            if service_statuses[service]['up'] and service_statuses[service]['available']:
                my_service_record['status'] = True
            else:
                my_service_record['status'] = False

            my_service_record['short_description'] = json.dumps(service_statuses[service])
            db_services.update_record(my_service_record, session=dbsession)

    return(True)

def get_status(service_record):
    global service_statuses
    hostid = service_record['hostid']
    servicename = service_record['servicename']
    base_url = service_record.get('base_url', 'N/A')
    service = '__'.join([hostid, servicename, base_url])

    if service in service_statuses:
        ret = service_statuses[service]
    else:
        raise Exception("no service status set for service: " + str(service))
    return(ret)

def handle_service_heartbeat(*args, **kwargs):
    cycle_timer = kwargs['mythread']['cycle_timer']
    localconfig = anchore_engine.configuration.localconfig.get_config()
    try:
        servicename = args[0]
    except Exception as err:
        raise Exception("BUG: need to provide service name as first argument to function: " + str(args))

    while(True):
        logger.debug("storing service status: " + str(servicename))
        try:
            logger.debug("local service record: {}".format(anchore_engine.subsys.servicestatus.get_my_service_record()))
            logger.debug("all service records: {}".format(service_statuses))

            service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
            update_status(service_record)
            logger.debug("service status update stored: next in "+str(cycle_timer))
        except Exception as err:
            logger.error(str(err))

        time.sleep(cycle_timer)

    return(True)

