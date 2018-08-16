from anchore_engine import db
from anchore_engine.db import Service

# specific DB interface helpers for the 'services' table

def make(session=None):
    if not session:
        session = db.Session

    return(Service().make())

def add(hostid, servicename, inobj, session=None):
    if not session:
        session = db.Session

    our_service = session.query(Service).filter_by(hostid=hostid).filter_by(servicename=servicename).first()

    if not our_service:
        new_service = Service(hostid=hostid, servicename=servicename)
        new_service.update(inobj)

        session.add(new_service)
    else:
        our_service.update(inobj)

    return(True)

def delete(hostid, servicename, session=None):
    our_service = session.query(Service).filter_by(hostid=hostid).filter_by(servicename=servicename).first()
    if our_service:
        session.delete(our_service)

    return(True)

# add and update amount to the same operation since we're using upserts                
def update(hostid, servicename, inobj, session=None):
    return(add(hostid, servicename, inobj, session=session))

def update_record(input_record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(Service).filter_by(hostid=input_record['hostid'], servicename=input_record['servicename']).first()
    if our_result:
        our_result.update(input_record)
        
    return(True)

# get all services from the DB for all registered services/hosts
def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Service)
    for result in our_results:
        ret.append(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))

    return(ret)

def get(hostid, servicename, base_url, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(Service).filter_by(hostid=hostid).filter_by(servicename=servicename).filter_by(base_url=base_url).first()
    if result:
        ret.update(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))

    return(ret)

def get_byname(servicename, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(Service).filter_by(servicename=servicename)
    if results:
        for result in results:
            dbobj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
            ret.append(dbobj)

    return(ret)

