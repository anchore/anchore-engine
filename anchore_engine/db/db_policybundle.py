from anchore_engine import db
from anchore_engine.db.entities.common import anchore_now
from anchore_engine.db import PolicyBundle


# specific DB interface helpers for the 'policybundle' table

def add(policyId, userId, active, inobj, session=None):
    if not session:
        session = db.Session

    inobj['active'] = active

    inobj.pop('last_updated', None)
    inobj.pop('created_at', None)
    our_result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).first()
    if not our_result:
        new_service = PolicyBundle(policyId=policyId, userId=userId)
        new_service.update(inobj)

        session.add(new_service)
    else:
        # Force an update here to cover updates even if content doesn't change.
        # This is probably worth revisiting later, to use a content digest to ensure changes actually
        inobj['last_updated'] = anchore_now()
        our_result.update(inobj)

    return(True)

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(PolicyBundle)
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get_all_byuserId(userId, limit=None, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(PolicyBundle).filter_by(userId=userId)
    if limit:
        our_results = our_results.limit(int(limit))

    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId
    
    results = session.query(PolicyBundle).filter_by(**dbfilter)
    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(obj)

    return(ret)

def get(userId, policyId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).first()
    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def get_active_policy(userId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(PolicyBundle).filter_by(userId=userId, active=True).first()
    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def set_active_policy(policyId, userId, session=None):
    if not session:
        session = db.Session

    ret = False

    result = session.query(PolicyBundle).filter(PolicyBundle.userId == userId).filter(PolicyBundle.policyId == policyId).first()
    if result:
        result.update({'active':True})

        results = session.query(PolicyBundle).filter(PolicyBundle.userId == userId).filter(PolicyBundle.policyId != policyId)
        for result in results:
            result.update({'active':False})

    return(True)

def update(policyId, userId, active, inobj, session=None):
    return(add(policyId, userId, active, inobj, session=session))

def update_record(input_record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(PolicyBundle).filter_by(policyId=input_record['policyId'], userId=input_record['userId']).first()
    if our_result:
        our_result.update(input_record)
        
    return(True)

def delete(policyId, userId, session=None):
    if not session:
        session = db.Session

    ret = False
    
    result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).first()
    if result:
        session.delete(result)
        ret = True

    return(ret)

