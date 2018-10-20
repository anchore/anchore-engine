"""
DB interface for Archive Document metadata.

Operations for CRUD on document references and metadata. Actual document content is stored by backend drivers (see: subsys.archive and subsys.object_store)
"""

import time
import urllib.parse
from anchore_engine import db
from anchore_engine.db import ArchiveMetadata
from anchore_engine.subsys import logger


def add(userId, bucket, archiveId, documentName, content_url=None, metadata=None, is_compressed=None, content_digest=None, size=None, session=None):
    if not session:
        session = db.Session

    doc_record = ArchiveMetadata(userId=userId, bucket=bucket, archiveId=archiveId, documentName=documentName, content_url=content_url, document_metadata=metadata, is_compressed=is_compressed, digest=content_digest, size=size)
    merged_result = session.merge(doc_record)
    return (True)


def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(ArchiveMetadata)
    for result in our_results:
        obj = dict((key, value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

    return (ret)


def get(userId, bucket, archiveId, session=None):
    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    if result:
        obj = dict((key, value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.update(obj)

    return (ret)


def get_onlymeta(userId, bucket, archiveId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    return result.to_dict()


def get_byname(userId, documentName, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, documentName=documentName).first()

    if result:
        obj = dict((key, value) for key, value in vars(result).items() if not key.startswith('_'))
        ret = obj

    return (ret)


def exists(userId, bucket, archiveId, session=None):
    """
    Return boolean on existence of a specific archive document in the system. Checks metadata only.

    :param userId:
    :param bucket:
    :param archiveId:
    :param session:
    :return:
    """
    if not session:
        session = db.Session

    ret = {}

    result = session.query(ArchiveMetadata).filter_by(userId=userId, bucket=bucket, archiveId=archiveId).first()
    return result is not None


def list_schemas(session=None):
    if not session:
        session = db.Session

    found_schemas = []

    for record in session.query(ArchiveMetadata.content_url):
        logger.info('Got record: {}'.format(record))
        parsed = urllib.parse.urlparse(record[0])
        found_schemas.append(parsed.scheme)

    return set(found_schemas)


def list_all_notempty(session=None):
    ret = []

    results = session.query(ArchiveMetadata).filter(ArchiveMetadata.content_url != None)
    for result in results:
        obj = {}
        for i in range(0, len(list(result.keys()))):
            k = list(result.keys())[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return (ret)


def list_all(session=None, **dbfilter):
    if not session:
        session = db.Session
    ret = []

    results = session.query(ArchiveMetadata).filter_by(**dbfilter)

    for result in results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)

        #obj = {}
        #for i in range(0, len(list(result.keys()))):
        #    k = list(result.keys())[i]
        #    obj[k] = result[i]
        #if obj:
        #    ret.append(obj)

    return (ret)


def list_all_byuserId(userId, limit=None, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter['userId'] = userId

    results = session.query(ArchiveMetadata).filter_by(**dbfilter)

    if limit:
        results = results.limit(int(limit))

    for result in results:
        obj = dict((key,value) for key, value in vars(result).items() if not key.startswith('_'))
        ret.append(obj)
        #obj = {}
        #for i in range(0, len(list(result.keys()))):
        #    k = list(result.keys())[i]
        #    obj[k] = result[i]
        #if obj:
        #    ret.append(obj)

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
