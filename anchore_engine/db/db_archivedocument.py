"""
This is a deprecated module. Archive model has changed to use the db_archivemeta module for meta record updates and db_objectstorage for the content.
"""

import time
from anchore_engine import db
from anchore_engine.db import ArchiveDocument


# specific DB interface helpers for the 'services' table

def add(userId, bucket, archiveId, documentName, inobj, session=None):
    if not session:
        session = db.Session

    our_result = session.query(ArchiveDocument).filter_by(userId=userId, bucket=bucket,archiveId=archiveId,documentName=documentName).first()
    if not our_result:
        new_service = ArchiveDocument(userId=userId, bucket=bucket,archiveId=archiveId,documentName=documentName)
        new_service.update(inobj)

        session.add(new_service)
    else:
        dbobj = {}
        dbobj.update(inobj)
        our_result.update(dbobj)
        dbobj.clear()

    return(True)

def get_all_iter(session=None):
    if not session:
        session = db.Session

    for top_result in session.query(ArchiveDocument.userId, ArchiveDocument.bucket, ArchiveDocument.archiveId):
        result = session.query(ArchiveDocument).filter_by(userId=top_result.userId, bucket=top_result.bucket, archiveId=top_result.archiveId).first()
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        yield obj

def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(ArchiveDocument)
    for result in our_results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return(ret)

def get(userId, bucket, archiveId, session=None):
    ret = {}

    result = session.query(ArchiveDocument).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.update(obj)

    return(ret)

def get_onlymeta(userId, bucket, archiveId, session=None):
    ret = {}

    result = session.query(ArchiveDocument.userId, ArchiveDocument.bucket, ArchiveDocument.archiveId, ArchiveDocument.record_state_key, ArchiveDocument.record_state_val, ArchiveDocument.created_at, ArchiveDocument.last_updated).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        for i in range(0, len(list(result.keys()))):
            k = list(result.keys())[i]
            ret[k] = result[i]

    return(ret)

def get_byname(userId, documentName, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveDocument).filter_by(userId=userId, documentName=documentName).first()

    if result:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return(ret)

def exists(userId, bucket, archiveId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveDocument.userId, ArchiveDocument.bucket, ArchiveDocument.archiveId).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()

    if result:
        for i in range(0, len(list(result.keys()))):
            k = list(result.keys())[i]
            ret[k] = result[i]

    return(ret)

def list_all_notempty(session=None):
    ret = []

    results = session.query(ArchiveDocument.bucket, ArchiveDocument.archiveId, ArchiveDocument.userId).filter(ArchiveDocument.jsondata != '{}')
    for result in results:
        obj = {}
        for i in range(0,len(list(result.keys()))):
            k = list(result.keys())[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)
    
    return(ret)

def list_all(session=None, **dbfilter):
    if not session:
        session = db.Session
    ret = []

    results = session.query(ArchiveDocument.bucket, ArchiveDocument.archiveId, ArchiveDocument.userId, ArchiveDocument.record_state_key, ArchiveDocument.record_state_val, ArchiveDocument.created_at, ArchiveDocument.last_updated).filter_by(**dbfilter)

    for result in results:
        obj = {}
        for i in range(0,len(list(result.keys()))):
            k = list(result.keys())[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return(ret)

def list_all_byuserId(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId

    results = session.query(ArchiveDocument.bucket, ArchiveDocument.archiveId, ArchiveDocument.userId, ArchiveDocument.record_state_key, ArchiveDocument.record_state_val, ArchiveDocument.created_at, ArchiveDocument.last_updated).filter_by(**dbfilter)

    for result in results:
        obj = {}
        for i in range(0,len(list(result.keys()))):
            k = list(result.keys())[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return(ret)

def update(userId, bucket, archiveId, documentName, inobj, session=None):
    return(add(userId, bucket, archiveId, documentName, inobj, session=session))

def delete_byfilter(userId, remove=True, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False
    
    results = session.query(ArchiveDocument).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})
            ret = True
    
    return(ret)

def delete(userId, bucket, archiveId, remove=True, session=None):
    if not session:
        session = db.Session

    result = session.query(ArchiveDocument).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        if remove:
            session.delete(result)
        else:
            result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})
    
    return(True)

