"""
DEPRECATED!
TODO: Remove this once upgrade code is in place
"""

import time

from anchore_engine import db
from anchore_engine.db import User


def add(userId, password, inobj, session=None):
    if not session:
        session = db.Session()
    
    #our_result = session.query(User).filter_by(userId=userId, password=password).first()
    our_result = session.query(User).filter_by(userId=userId).first()
    if not our_result:
        our_result = User(userId=userId, password=password)

        if 'created_at' not in inobj:
            inobj['created_at'] = int(time.time())

        our_result.update(inobj)

        session.add(our_result)
    else:
        inobj['password'] = password
        our_result.update(inobj)

    return(True)

def get_all(session=None):
    if not session:
        session = db.Session()

    ret = []

    our_results = session.query(User).filter_by()
    for result in our_results:
        obj = {}
        obj.update(dict((key,value) for key, value in vars(result).items() if not key.startswith('_')))
        ret.append(obj)

    return(ret)

def get(userId, session=None):
    if not session:
        session = db.Session()

    ret = {}

    result = session.query(User).filter_by(userId=userId).first()

    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def update(userId, password, inobj, session=None):
    return(add(userId, password, inobj, session=session))

def delete(userId, session=None):
    if not session:
        session = db.Session()

    ret = False
    
    result = session.query(User).filter_by(userId=userId).first()
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

