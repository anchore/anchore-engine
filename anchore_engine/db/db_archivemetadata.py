"""
DB interface for Archive Document metadata.

Operations for CRUD on document references and metadata. Actual document content is stored by backend drivers (see: subsys.archive and subsys.object_store)
"""

import time
from anchore_engine import db
from anchore_engine.db import ArchiveMetadata


def add(userId, bucket, archiveId, documentName, content_url=None, metadata=None, is_compressed=None, content_digest=None, size=None, session=None):
    if not session:
        session = db.Session

    doc_record = ArchiveMetadata(userId=userId, bucket=bucket, archiveId=archiveId, documentName=documentName, content_url=content_url, document_metadata=metadata, is_compressed=is_compressed, digest=content_digest, size=size)
    merged_result = session.merge(doc_record)
    return (True)


def get_all_iter(session=None):
    if not session:
        session = db.Session

    for top_result in session.query(ArchiveMetadata.userId, ArchiveMetadata.bucket, ArchiveMetadata.archiveId):
        result = session.query(ArchiveMetadata).filter_by(userId=top_result.userId, bucket=top_result.bucket, archiveId=top_result.archiveId).first()
        obj = dict((key, value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        yield obj


def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(ArchiveMetadata)
    for result in our_results:
        obj = dict((key, value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.append(obj)

    return (ret)


def get(userId, bucket, archiveId, session=None):
    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        obj = dict((key, value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret.update(obj)

    return (ret)


def get_onlymeta(userId, bucket, archiveId, session=None):
    ret = {}

    result = session.query(ArchiveMetadata.userId, ArchiveMetadata.bucket, ArchiveMetadata.archiveId, ArchiveMetadata.record_state_key, ArchiveMetadata.record_state_val, ArchiveMetadata.created_at,
                           ArchiveMetadata.last_updated).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        for i in range(0, len(result.keys())):
            k = result.keys()[i]
            ret[k] = result[i]

    return (ret)


def get_byname(userId, documentName, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, documentName=documentName).first()

    if result:
        obj = dict((key, value) for key, value in vars(result).iteritems() if not key.startswith('_'))
        ret = obj

    return (ret)


def exists(userId, bucket, archiveId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveMetadata.userId, ArchiveMetadata.bucket, ArchiveMetadata.archiveId).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()

    if result:
        for i in range(0, len(result.keys())):
            k = result.keys()[i]
            ret[k] = result[i]

    return (ret)


def list_all_notempty(session=None):
    ret = []

    results = session.query(ArchiveMetadata.bucket, ArchiveMetadata.archiveId, ArchiveMetadata.userId).filter(ArchiveMetadata.content_url != None)
    for result in results:
        obj = {}
        for i in range(0, len(result.keys())):
            k = result.keys()[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return (ret)


def list_all(session=None, **dbfilter):
    if not session:
        session = db.Session
    ret = []

    results = session.query(ArchiveMetadata.bucket, ArchiveMetadata.archiveId, ArchiveMetadata.userId, ArchiveMetadata.record_state_key, ArchiveMetadata.record_state_val, ArchiveMetadata.created_at,
                            ArchiveMetadata.last_updated).filter_by(**dbfilter)

    for result in results:
        obj = {}
        for i in range(0, len(result.keys())):
            k = result.keys()[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return (ret)


def list_all_byuserId(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId

    results = session.query(ArchiveMetadata.bucket, ArchiveMetadata.archiveId, ArchiveMetadata.userId, ArchiveMetadata.record_state_key, ArchiveMetadata.record_state_val, ArchiveMetadata.created_at,
                            ArchiveMetadata.last_updated).filter_by(**dbfilter)

    for result in results:
        obj = {}
        for i in range(0, len(result.keys())):
            k = result.keys()[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return (ret)


def update(userId, bucket, archiveId, documentName, content_url=None, metadata=None, session=None):
    return (add(userId, bucket, archiveId, documentName, content_url, metadata, session=session))


def delete_byfilter(userId, remove=True, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False

    results = session.query(ArchiveMetadata).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})
            ret = True

    return (ret)


def delete(userId, bucket, archiveId, remove=True, session=None):
    if not session:
        session = db.Session

    result = session.query(ArchiveMetadata).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        if remove:
            session.delete(result)
        else:
            result.update({"record_state_key": "to_delete", "record_state_val": str(time.time())})

    return (True)
