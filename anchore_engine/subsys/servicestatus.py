from anchore_engine.db import db_services, session_scope
import json 

service_statuses = {}

def set_status(service_record, up=True, available=True, busy=False, message="all good", detail={}, update_db=False):
    global service_statuses
    hostid = service_record['hostid']
    servicename = service_record['servicename']
    service = '__'.join([service_record['hostid'], service_record['servicename']])

    if service not in service_statuses:
        service_statuses[service] = {}

    service_statuses[service]['up']= up
    service_statuses[service]['available'] = available
    service_statuses[service]['busy'] = busy 
    service_statuses[service]['message'] = message
    if detail:
        service_statuses[service]['detail'] = detail

    if update_db:
        with session_scope() as dbsession:
            my_service_record = db_services.get(hostid, servicename, session=dbsession)
            if my_service_record:
                my_service_record['short_description'] = json.dumps(service_statuses[service])
                db_services.update_record(my_service_record, session=dbsession)

def get_status(service_record):
    global service_statuses
    service = '__'.join([service_record['hostid'], service_record['servicename']])

    if service in service_statuses:
        ret = service_statuses[service]
    else:
        raise Exception("no service status set for service: " + str(service))
    return(ret)

def initialize_status(service_record, up=True, available=True, busy=False, message="all good", detail={}):
    global service_statuses
    service = '__'.join([service_record['hostid'], service_record['servicename']])
    if service not in service_statuses:
        set_status(service_record, up=up, available=available, busy=busy, message=message, detail=detail)
    return(True)

def has_status(service_record):
    global service_statuses
    service = '__'.join([service_record['hostid'], service_record['servicename']])
    ret = False
    if service in service_statuses:
        ret = True

    return(ret)
