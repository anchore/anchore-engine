import copy
import datetime
import hashlib
import json
import uuid

from sqlalchemy import asc, desc, or_, and_

from anchore_engine import db
from anchore_engine.db import Queue, QueueMeta

from anchore_engine.subsys import logger
from anchore_engine.subsys.caching import local_named_cache


def config_cache():
    return local_named_cache('queue_configs')


def _to_dict(obj):
    if obj is None:
        return None
    else:
        return dict((key, value) for key, value in vars(obj).items() if not key.startswith('_'))


def create(queueName, userId, session=None, max_outstanding_msgs=-1, visibility_timeout=0):
    if not session:
        session = db.Session

    ret = {}

    record = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
    if not record:
        newrecord = QueueMeta(queueName=queueName, userId=userId, max_outstanding_messages=max_outstanding_msgs, visibility_timeout=visibility_timeout)
        session.add(newrecord)
        record = newrecord


    if record:
        ret = _to_dict(record)
        config_cache().cache_it(key=(userId, queueName), obj=copy.deepcopy(ret))
        
    return(ret)


def generate_dataId(inobj):
    datajson = json.dumps(inobj)
    dataId = hashlib.md5(datajson.encode('utf-8')).hexdigest()
    return(dataId, datajson)


def is_inqueue(queueName, userId, data, session=None):
    if not session:
        session = db.Session

    ret = {}

    dataId, datajson = generate_dataId(data)
    result = session.query(Queue).filter_by(queueName=queueName, userId=userId, dataId=dataId).first()
    if result:
        dbobj = _to_dict(result)
        ret.update(dbobj)
        ret['data'] = json.loads(dbobj['data'])

    return(ret)
    

def enqueue(queueName, userId, data, qcount=0, max_qcount=0, priority=False, session=None):
    if not session:
        session = db.Session

    # Use the queue meta record as the lock for queue insertion/deletion since we are tracking queue length and count of
    # outstanding messages
    metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()

    dataId, datajson = generate_dataId(data)
    new_service = Queue(queueName=queueName, userId=userId, data=datajson, dataId=dataId, priority=priority, tries=qcount, max_tries=max_qcount)

    session.add(new_service)
    
    rcount = session.query(Queue).filter_by(queueName=queueName, userId=userId).count()
    metarecord.update({'qlen': rcount})

    return(True)


def dequeue(queueName, userId, visibility_timeout=None, session=None):
    """
    Dequeue subject to queue configuration (max_outstanding_message and vis timeout).
    If queue's max_outstanding_messages > 0 then messages are hidden and returned with a receipt handle rather than deleting the message.

    :param queueName:
    :param userId:
    :param session:
    :return:
    """
    if not session:
        session = db.Session

    ret = {}

    # Is it cached?
    cached_record = config_cache().lookup(key=(userId, queueName))
    if cached_record:
        outstanding_count_setting = cached_record['max_outstanding_messages']
    else:
        metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
        config_cache().cache_it(key=(userId, queueName), obj=copy.deepcopy(_to_dict(metarecord)))
        outstanding_count_setting = metarecord.max_outstanding_messages
        metarecord = None

    if outstanding_count_setting < 0:
        metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
        result = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId, popped=False).order_by(desc(Queue.priority)).order_by(asc(Queue.queueId)).first()

        if result:
            result.update({'popped': True})
            dbobj = _to_dict(result)
            ret.update(dbobj)
            ret['data'] = json.loads(dbobj['data'])
            session.delete(result)

            # Only update the count if returning a message
            if ret:
                rcount = session.query(Queue).filter_by(queueName=queueName, userId=userId, popped=False).count()
                metarecord.update({'qlen': rcount})
    else:
        # Flush the record from the session and memory. Then reload it with a lock
        # Refetch with lock
        metarecord = session.query(QueueMeta).with_for_update(of=QueueMeta).filter_by(queueName=queueName, userId=userId).first()

        # Limits are configured on this queue, do appropriate checks
        if _not_visible_msg_count(queueName, userId, session) < int(metarecord.max_outstanding_messages):
            # Will select any unpopped or popped-but-expired messages
            result = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId).filter(or_(and_(Queue.visible_at<=datetime.datetime.utcnow(), Queue.popped==True), Queue.popped==False)).order_by(desc(Queue.priority)).order_by(asc(Queue.queueId)).first()

            if result:
                if visibility_timeout is None:
                    visibility_timeout = metarecord.visibility_timeout

                result.update({'popped': True, 'receipt_handle': uuid.uuid4().hex, 'visible_at': datetime.datetime.utcnow() + datetime.timedelta(seconds=visibility_timeout)})
                dbobj = _to_dict(result)
                ret.update(dbobj)
                ret['data'] = json.loads(dbobj['data'])

            # Don't update qlen until the message is deleted from the queue with an explicit delete operation
        else:
            # Threshold of outstanding messages exceeded.
            pass

    return(ret)


def _not_visible_msg_count(queueName, userId, session):
    outstanding = session.query(Queue).filter_by(queueName=queueName, userId=userId).filter(Queue.popped==True, Queue.visible_at>datetime.datetime.utcnow()).count()
    return outstanding


def delete_msg_by_handle(queueName, userId, receipt_handle, session=None):
    if not session:
        session = db.Session

    metarecord = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
    obj = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId, receipt_handle=receipt_handle, popped=True).one_or_none()
    if obj:
        session.delete(obj)
        rcount = session.query(Queue).filter_by(queueName=queueName, userId=userId, popped=False).count()
        metarecord.update({'qlen': rcount})
        return True
    else:
        return False


def update_visibility_by_handle(queueName, userId, receipt_handle, visibility_timeout, session=None):
    if not session:
        session = db.Session

    queueMeta = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).first()
    if not queueMeta:
        return False

    obj = session.query(Queue).with_for_update(of=Queue).filter_by(queueName=queueName, userId=userId, receipt_handle=receipt_handle, popped=True).one_or_none()
    if obj:
        t = datetime.datetime.utcnow() + datetime.timedelta(seconds=visibility_timeout)
        obj.update({'visible_at': t})
        return t.isoformat()
    else:
        return False


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
        ret.append(_to_dict(result))

    return(ret)


def get_byuserId(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Queue).filter_by(userId=userId)
    for result in our_results:
        ret.append(_to_dict(result))

    return(ret)


def get_queue(queueName, userId, session=None):
    if not session:
        session = db.Session

    q = session.query(QueueMeta).filter_by(queueName=queueName, userId=userId).one_or_none()
    return _to_dict(q)
