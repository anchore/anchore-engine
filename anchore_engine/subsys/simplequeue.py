
from anchore_engine import db
from anchore_engine.db import db_queue

queues = {}
queues_persist_files = {}

def create_queue(name, persist_location=None):
    try:
        with db.session_scope() as dbsession:
            db_queue.create(name, 'system', session=dbsession)
    except Exception as err:
        raise err
            
    return(True)

def get_queuenames():
    ret = []

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.get_queuenames('system', session=dbsession)
    except Exception as err:
        raise err

    return(ret)

def qlen(name):
    queuenames = get_queuenames()
    
    if name not in queuenames:
        return(0)

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.get_qlen(name, 'system', session=dbsession)
    except Exception as err:
        raise err

    return(ret)
    
def enqueue(name, inobj, qcount=0, forcefirst=False):
    ret = {}

    queuenames = get_queuenames()

    if name in queuenames:
        try:
            with db.session_scope() as dbsession:
                ret = db_queue.enqueue(name, 'system', inobj, qcount=qcount, priority=forcefirst, session=dbsession)
        except Exception as err:
            raise err

    return(ret)

def dequeue(name):
    ret = {}
    queuenames = get_queuenames()

    if name not in queuenames or qlen(name) <= 0:
        return(None)
        
    try:
        with db.session_scope() as dbsession:
            ret = db_queue.dequeue(name, 'system', session=dbsession)
    except Exception as err:
        raise err

    return(ret)

def is_inqueue(name, inobj):
    ret = {}
    queuenames = get_queuenames()

    if name not in queuenames:
        return({})

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.is_inqueue(name, 'system', inobj, session=dbsession)
    except Exception as err:
        raise err
        
    return(ret)
