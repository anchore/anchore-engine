import hashlib
import time

from anchore_engine import db
from anchore_engine.db import Subscription


def add(userId, subscription_key, subscription_type, inobj, session=None):
    if not session:
        session = db.Session

    # prep the input object
    if not inobj:
        inobj = {}

    subscription_id = hashlib.md5('+'.join([userId, subscription_key, subscription_type]).encode('utf-8')).hexdigest()
    inobj['subscription_id'] = subscription_id

    inobj.pop('userId', None)
    inobj.pop('last_updated', None)
    inobj.pop('created_at', None)

    our_result = session.query(Subscription).filter_by(subscription_id=subscription_id, userId=userId,
                                                       subscription_key=subscription_key,
                                                       subscription_type=subscription_type).first()
    if not our_result:
        our_result = Subscription(subscription_id=subscription_id, userId=userId, subscription_key=subscription_key,
                                  subscription_type=subscription_type)

        our_result.update(inobj)
        session.add(our_result)
    else:
        our_result.update(inobj)

    return (True)


def get_all_byuserId(userId, limit=None, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Subscription).filter_by(userId=userId)
    if limit:
        our_results = our_results.limit(int(limit))

    for result in our_results:
        ret.append(result.to_dict())

    return (ret)


def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Subscription)
    for result in our_results:
        ret.append(result.to_dict())

    return (ret)


def get(userId, subscription_id, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(Subscription).filter_by(userId=userId, subscription_id=subscription_id).first()

    if result:
        ret = result.to_dict()

    return (ret)


def get_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId

    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            ret.append(result.to_dict())

    return (ret)


def get_bysubscription_key(userId, subscription_key, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(Subscription).filter_by(userId=userId, subscription_key=subscription_key)

    if results:
        for result in results:
            obj = dict((key, value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(obj)

    return (ret)


def update(userId, subscription_key, subscription_type, inobj, session=None):
    return (add(userId, subscription_key, subscription_type, inobj, session=session))


def delete(userId, subscriptionId, remove=False, session=None):
    if not session:
        session = db.Session

    ret = False

    dbfilter = {'userId': userId, 'subscription_id': subscriptionId}
    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})

            ret = True

    return (ret)


def delete_bysubscription_key(userId, subscription_key, remove=False, session=None):
    if not session:
        session = db.Session

    ret = False

    results = session.query(Subscription).filter_by(userId=userId, subscription_key=subscription_key)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})

            ret = True

    return (ret)


def delete_byfilter(userId, remove=False, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False

    dbfilter['userId'] = userId

    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})
            ret = True

    return (ret)
