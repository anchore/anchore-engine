from anchore_engine import db
from anchore_engine.db import Anchore


# for the Anchore class/table

def get(session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(Anchore).first()

    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def add(service_version, db_version, inobj, session=None):
    if not session:
        session = db.Session

    #our_result = session.query(Anchore).filter_by(service_version=service_version, db_version=db_version).first()
    our_result = session.query(Anchore).first()
    if not our_result:
        new_service = Anchore(service_version=service_version, db_version=db_version)
        new_service.update(inobj)

        session.add(new_service)
    else:
        inobj['service_version'] = service_version
        inobj['db_version'] = db_version
        our_result.update(inobj)

#    try:
#        session.commit()
#    except Exception as err:
#        raise err
#    finally:
#        session.rollback()
    
    return(True)

def update(service_version, db_version, scanner_version, inobj, session=None):
    return(add(service_version, db_version, scanner_version, inobj, session=session))

def update_record(input_record, session=None):
    if not session:
        session = db.Session

    our_result = session.query(Anchore).filter_by(service_version=input_record['service_version'], db_version=input_record['db_version']).first()
    if our_result:
        our_result.update(input_record)
        
    return(True)
