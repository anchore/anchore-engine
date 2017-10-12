import json
import hashlib
import json

from sqlalchemy import asc

from anchore_engine import db
from anchore_engine.db import Queue, QueueMeta


# specific DB interface helpers for the 'services' table

def create(queueName, userId, session=None):
    if not session:
        session = db.Session

    ret = {}

    record = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
    if not record:
        newrecord = QueueMeta(queueName=queueName, userId=userId)
        session.add(newrecord)
        record = newrecord

    if record:
        ret = dict((key,value) for key, value in vars(record).iteritems() if not key.startswith('_'))
        
    return(ret)

def generate_dataId(inobj):
    datajson = json.dumps(inobj)
    dataId = hashlib.md5(datajson).hexdigest()
    return(dataId, datajson)

def is_inqueue(queueName, userId, data, session=None):
    if not session:
        session = db.Session

    ret = {}

    dataId, datajson = generate_dataId(data)
    result = session.query(Queue).filter_by(queueName=queueName, userId=userId, dataId=dataId).first()
    if result:
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.update(dbobj)
        ret['data'] = json.loads(dbobj['data'])

    return(ret)
    

def enqueue(queueName, userId, data, qcount=0, max_qcount=0, priority=False, session=None):
    if not session:
        session = db.Session

    #queueId = hashlib.md5('+'.join([userId, queueName, json.dumps(inobj)])).hexdigest()
    #our_service = session.query(Queue).filter_by(queueName=queueName, userId=userId).first()
    #if not our_service:
    metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()

    #datajson = json.dumps(data)
    dataId, datajson = generate_dataId(data) #hashlib.md5('+'.join([userId, queueName, datajson])).hexdigest()
    new_service = Queue(queueName=queueName, userId=userId, data=datajson, dataId=dataId, priority=priority, tries=qcount, max_tries=max_qcount)

    session.add(new_service)
    
    rcount = session.query(Queue).filter_by(queueName=queueName, userId=userId).count()
    metarecord.update({'qlen': rcount})

    return(True)

def dequeue(queueName, userId, session=None):
    if not session:
        session = db.Session

    #from sqlalchemy.sql.expression import func
    ret = {}

    metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()

    result = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId, popped=False, priority=True).order_by(asc(Queue.queueId)).first()
    if not result:
        result = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId, popped=False).order_by(asc(Queue.queueId)).first()

    if result:
        result.update({'popped': True})
        dbobj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.update(dbobj)
        ret['data'] = json.loads(dbobj['data'])
        #ret = json.loads(dbobj['data'])
        session.delete(result)

    rcount = session.query(Queue).filter_by(queueName=queueName, userId=userId).count()
    metarecord.update({'qlen': rcount})

    return(ret)

def get_qlen(queueName, userId, session=None):
    if not session:
        session = db.Session    

    ret = session.query(Queue).filter_by(queueName=queueName, userId=userId).count()

    return(int(ret))

def get_queuenames(userId, session=None):
    if not session:
        session = db.Session

    ret = []
    records = session.query(QueueMeta).filter_by(userId=userId)
    for record in records:
        ret.append(record.queueName)

    return(ret)

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Queue)
    for result in our_results:
        ret.append(dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_')))

    return(ret)

def get_byuserId(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Queue).filter_by(userId=userId)
    for result in our_results:
        ret.append(dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_')))

    return(ret)

