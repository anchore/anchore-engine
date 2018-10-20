from anchore_engine import db
from anchore_engine.db import Registry
#from db import Base

#Base = declarative_base()

# specific DB interface helpers for the 'services' table

def add(registry, userId, inobj, session=None):
    if not session:
        session = db.Session

    our_service = session.query(Registry).filter_by(registry=registry, userId=userId).first()

    if not our_service:
        new_service = Registry(registry=registry, userId=userId)
        new_service.update(inobj)
        session.add(new_service)
    else:
        our_service.update(inobj)

    return(True)

def delete(registry, userId, session=None):
    if not session:
        session = db.Session

    our_service = session.query(Registry).filter_by(registry=registry, userId=userId).first()
    if our_service:
        session.delete(our_service)

    return(True)

# add and update amount to the same operation since we're using upserts                
def update(registry, userId, inobj, session=None):
    return(add(registry, userId, inobj, session=session))

def update_record(input_record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(Registry).filter_by(registry=input_record['registry'], userId=input_record['userId']).first()
    if our_result:
        our_result.update(input_record)
        
    return(True)

# get all services from the DB for all registered services/hosts
def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Registry)
    for result in our_results:
        ret.append(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))

    return(ret)

def get_all_byuserId(userId, limit=None, session=None):
    return(get_byuserId(userId, limit=limit, session=session))

def get_byuserId(userId, limit=None, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Registry).filter_by(userId=userId)
    if limit:
        our_results = our_results.limit(int(limit))
        
    for result in our_results:
        ret.append(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))

    return(ret)
    
def get(registry, userId, session=None):
    if not session:
        session = db.Session

    ret = []

    record = {}
    result = session.query(Registry).filter_by(registry=registry, userId=userId).first()
    if result:
        record.update(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))

    if record:
        ret.append(record)

    return(ret)
