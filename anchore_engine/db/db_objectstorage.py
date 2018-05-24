import json
from anchore_engine import db
from anchore_engine.db import ObjectStorageRecord


def put(userId, bucket, key, data, metadata=None, session=None):
    if not session:
        session = db.Session

    our_result = session.query(ObjectStorageRecord).filter_by(userId=userId, bucket=bucket, key=key).one_or_none()
    if not our_result:
        if metadata:
            meta = json.dumps(metadata)
        else:
            meta = None

        obj = ObjectStorageRecord(userId=userId, bucket=bucket, key=key, metadata=meta)
        obj.content = data
        session.add(obj)
        return True
    else:
        # No way to remove data, use delete if that is desired. This allows updating metadata only if needed by not including data
        if data is not None:
            our_result.content = data

        if metadata:
            our_result.metadata = json.dumps(metadata)

        return True


def get(userId, bucket, key, session=None):
    result = session.query(ObjectStorageRecord).filter_by(userId=userId, bucket=bucket, key=key).first()
    return result.to_dict() if result else None


def get_metadata(userId, bucket, key, session=None):
    ret = {}

    result = session.query(ObjectStorageRecord.userId, ObjectStorageRecord.bucket, ObjectStorageRecord.key, ObjectStorageRecord.object_metadata, ObjectStorageRecord.created_at, ObjectStorageRecord.last_updated).filter_by(userId=userId, bucket=bucket, key=key).first()
    if result:
        for i in range(0, len(list(result.keys()))):
            k = list(result.keys())[i]
            if i == 'object_metadata':
                ret[k] = json.loads(result[i])
            else:
                ret[k] = result[i]
    return (ret)


def exists(userId, bucket, key, session=None):
    if not session:
        session = db.Session

    result = session.query(ObjectStorageRecord.userId, ObjectStorageRecord.bucket, ObjectStorageRecord.key).filter_by(userId=userId, bucket=bucket, key=key).first()
    return result is not None


def list_all(session=None, **dbfilter):
    if not session:
        session = db.Session
    ret = []

    results = session.query(ObjectStorageRecord.bucket, ObjectStorageRecord.key, ObjectStorageRecord.userId, ObjectStorageRecord.record_state_key, ObjectStorageRecord.record_state_val,
                            ObjectStorageRecord.created_at, ObjectStorageRecord.last_updated).filter_by(**dbfilter)

    for result in results:
        obj = {}
        for i in range(0, len(list(result.keys()))):
            k = list(result.keys())[i]
            obj[k] = result[i]
        if obj:
            ret.append(obj)

    return (ret)


def delete(userId, bucket, key, session=None):
    if not session:
        session = db.Session

    result = session.query(ObjectStorageRecord).filter_by(userId=userId, bucket=bucket, key=key).first()
    if result:
        session.delete(result)

    return (True)
