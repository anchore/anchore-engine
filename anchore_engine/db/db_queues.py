import json
import time

from sqlalchemy import asc

from anchore_engine import db
from anchore_engine.db import QueueItem


def add(queueId, userId, dataId, data, tries, max_tries, session=None):
    if not session:
        session = db.Session

    our_result = session.query(QueueItem).filter_by(queueId=queueId, userId=userId, dataId=dataId).first()
    if not our_result:
        our_result = QueueItem(queueId=queueId, userId=userId, dataId=dataId, data=json.dumps(data), tries=tries, max_tries=max_tries, created_at=time.time())

        #our_result.update(inobj)

        session.add(our_result)
    #else:
    #    our_result.update(inobj)

    return(True)

def add_record(queue_record, session=None):
    return(add(queue_record['queueId'], queue_record['userId'], queue_record['dataId'], queue_record['data'], queue_record['tries'], queue_record['max_tries'], session=session))

def get_all(queueId, userId, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(QueueItem).filter_by(queueId=queueId, userId=userId).order_by(asc(QueueItem.created_at))
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        obj['data'] = json.loads(obj['data'])
        ret.append(obj)
        #session.delete(result)

    return(ret)

def drain_all(queueId, userId, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(QueueItem).filter_by(queueId=queueId, userId=userId).order_by(asc(QueueItem.created_at))
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        obj['data'] = json.loads(obj['data'])
        ret.append(obj)
        session.delete(result)

    return(ret)

def update_record(queue_record, session=None):
    if not session:
        session = db.Session

    result = session.query(QueueItem).filter_by(queueId=queue_record['queueId'], userId=queue_record['userId'], dataId=queue_record['dataId']).first()
    if result:
        dbobj = {}
        dbobj.update(queue_record)
        dbobj['data'] = json.dumps(queue_record['data'])
        result.update(dbobj)

    return(True)

def delete_record(queue_record, session=None):
    if not session:
        session = db.Session

    ret = False
    
    result = session.query(QueueItem).filter_by(queueId=queue_record['queueId'], userId=queue_record['userId'], dataId=queue_record['dataId']).first()
    if result:
        session.delete(result)
        ret = True
    
    return(ret)

