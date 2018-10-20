import time

from sqlalchemy import desc

from anchore_engine import db
from anchore_engine.db import PolicyEval

# specific DB interface helpers for the 'policyeval' table

def tsadd(policyId, userId, imageDigest, tag, final_action, inobj, session=None):
    if not session:
        session = db.Session

    latest_result = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag).order_by(desc(PolicyEval.created_at)).first()
    new_result = PolicyEval(userId=userId, imageDigest=imageDigest, tag=tag, policyId=policyId, final_action=final_action, created_at=int(time.time()))
    new_result.update(inobj)

    if latest_result:
        rc = latest_result.content_compare(new_result)
        if rc:
            # same - update old object
            latest_result.update({'created_at':int(time.time())})
        else:
            # different, make new object
            session.add(new_result)
    else:
        # brand new object
        session.add(new_result)

#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()

    return(True)

def tsget_all(userId, imageDigest, tag, policyId=None, session=None):
    if not session:
        session = db.Session

    ret = []

    if policyId:
        results = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag).order_by(desc(PolicyEval.created_at))

    else:
        results = session.query(PolicyEval).filter_by(userId=userId, imageDigest=imageDigest, tag=tag).order_by(desc(PolicyEval.created_at))

    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(obj)

    return(ret)

def tsget_all_bytag(userId, tag, policyId=None, session=None):
    if not session:
        session = db.Session

    ret = []

    if policyId:
        results = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, tag=tag).order_by(desc(PolicyEval.created_at))
    else:
        results = session.query(PolicyEval).filter_by(userId=userId, tag=tag).order_by(desc(PolicyEval.created_at))

    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(obj)

    return(ret)


def tsget_latest(userId, imageDigest, tag, policyId=None, session=None):
    if not session:
        session = db.Session

    ret = {}
    results = tsget_all(userId, imageDigest, tag, policyId=policyId, session=session)
    if results:
        ret = results[0]

    return(ret)

def tsget_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId
    
    results = session.query(PolicyEval).filter_by(**dbfilter).order_by(desc(PolicyEval.created_at))
    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(obj)

    return(ret)

def add(policyId, userId, imageDigest, tag, final_action, created_at, inobj, session=None):
    if not session:
        session = db.Session

    our_result = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag, final_action=final_action, created_at=created_at).first()
    if not our_result:
        new_service = PolicyEval(userId=userId, imageDigest=imageDigest, tag=tag, policyId=policyId, final_action=final_action, created_at=created_at)
        new_service.update(inobj)

        session.add(new_service)
    else:
        our_result.update(inobj)

#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()
    
    return(True)

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(PolicyEval)
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get_all_byuserId(userId, limit=None, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(PolicyEval).filter_by(userId=userId)
    if limit:
        our_results = our_results.limit(int(limit))

    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get(userId, imageDigest, tag, policyId=None, session=None):
    if not session:
        session = db.Session

    ret = {}

    if policyId:
        result = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag).order_by(desc(PolicyEval.created_at)).first()

    else:
        result = session.query(PolicyEval).filter_by(userId=userId, imageDigest=imageDigest, tag=tag).order_by(desc(PolicyEval.created_at)).first()

    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def update(policyId, userId, imageDigest, tag, final_action, created_at, inobj, session=None):
    if not session:
        session = db.Session

    our_result = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag, final_action=final_action).order_by(desc(PolicyEval.created_at)).first()
    if not our_result:
        return(add(policyId, userId, imageDigest, tag, final_action, created_at, inobj))
    else:
        inobj['created_at'] = created_at
        our_result.update(inobj)

    return(True)

def delete_record(input_record, session=None):
    if not session:
        session = db.Session
        
    ret = False

    result = session.query(PolicyEval).filter_by(**input_record).order_by(desc(PolicyEval.created_at)).first()
    if result:
        session.delete(result)
        ret = True

    return(ret)

def delete_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False

    dbfilter['userId'] = userId
    
    results = session.query(PolicyEval).filter_by(**dbfilter).order_by(desc(PolicyEval.created_at))
    if results:
        for result in results:
            session.delete(result)
            ret = True

    return(ret)

def delete(userId, imageDigest, tag, policyId=None, session=None):
    if not session:
        session = db.Session

    ret = False
    
    if policyId:
        result = session.query(PolicyEval).filter_by(policyId=policyId, userId=userId, imageDigest=imageDigest, tag=tag).first()
    else:
        result = session.query(PolicyEval).filter_by(userId=userId, imageDigest=imageDigest, tag=tag).first()

    if result:
        session.delete(result)
        ret = True
#        try:
#            session.commit()
#            ret = True
#        except Exception as err:
#            raise err
#        finally:
#            session.rollback()
    
    return(ret)
