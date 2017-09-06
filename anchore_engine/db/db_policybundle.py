from anchore_engine import db
from anchore_engine.db import PolicyBundle
#from db import Base

#Base = declarative_base()

# specific DB interface helpers for the 'services' table

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
        our_result.update(inobj)

#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()
    
    return(True)

def get_all(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(PolicyBundle).filter_by(userId=userId)
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId
    
    results = session.query(PolicyBundle).filter_by(**dbfilter)
    #results = session.query(Subscription).filter_by(userId=userId, subscription_key=subscription_key)
    if results:
        for result in results:
            obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
            ret.append(obj)

    return(ret)

def get(policyId, userId, active=True, session=None):
    if not session:
        session = db.Session

    ret = {}

    #result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).filter_by(active=active).first()
    result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).first()
    if result:
        obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret = obj

    return(ret)

def get_active_policy(userId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(PolicyBundle).filter_by(userId=userId, active=True).first()
    if result:
        obj = dict((key,value) for key, value in vars(result).iteritems() if not key.startswith('_'))
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
        
#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()

    return(True)

def update(policyId, userId, active, inobj, session=None):
    return(add(policyId, userId, active, inobj, session=session))

def delete(policyId, userId, session=None):
    if not session:
        session = db.Session

    ret = False
    
    result = session.query(PolicyBundle).filter_by(policyId=policyId).filter_by(userId=userId).first()
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

