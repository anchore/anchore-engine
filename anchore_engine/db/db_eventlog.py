import time

from anchore_engine import db
from anchore_engine.db import EventLog


def add(hostId, service_name, message, level, inobj, session=None):
    if not session:
        session = db.Session

    inobj['message_ts'] = int(time.time())

    dbfilter = {
        'hostId':hostId,
        'service_name':service_name,
        'message':message,
        'level':level
    }
    our_result = session.query(EventLog).filter_by(**dbfilter).first()
    if not our_result:
        our_result = EventLog(**dbfilter)
        our_result.update(inobj)
        session.add(our_result)
    else:
        our_result.update(inobj)

    return(True)

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(EventLog)
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get(hostId, service_name, message, level, session=None):
    if not session:
        session = db.Session

    ret = {}

    dbfilter = {
        'hostId':hostId,
        'service_name':service_name,
        'message':message,
        'level':level
    }
    result = session.query(EventLog).filter_by(**dbfilter).first()

    if result:
        obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret = obj

    return(ret)

def get_byfilter(session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    results = session.query(EventLog).filter_by(**dbfilter)
    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            ret.append(obj)

    return(ret)


def update(hostId, service_name, message, level, inobj, session=None):
    return(add(hostId, service_name, message, level, inobj, session=session))

def delete_record(event_record, session=None):
    return(delete(event_record['hostId'], event_record['service_name'], event_record['message'], event_record['level'], session=session))

def delete_byfilter(session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False
    results = session.query(EventLog).filter_by(**dbfilter)
    if results:
        for result in results:
            session.delete(result)
            ret = True

    return(ret)

def delete(hostId, service_name, message, level, session=None):
    if not session:
        session = db.Session

    ret = False
    
    dbfilter = {
        'hostId':hostId,
        'service_name':service_name,
        'message':message,
        'level':level
    }
    results = session.query(EventLog).filter_by(**dbfilter)
    if results:
        for result in results:
            session.delete(result)
            ret = True
    
    return(ret)
