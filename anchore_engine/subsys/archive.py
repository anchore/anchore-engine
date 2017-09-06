import json
import os

import anchore_engine.configuration.localconfig
from anchore_engine import db
from anchore_engine.db import db_archivedocument
from anchore_engine.subsys import logger

use_db = False
data_volume = None
archive_initialized = False

def initialize():
    global archive_initialized, data_volume, use_db

    localconfig = anchore_engine.configuration.localconfig.get_config()
    myconfig = localconfig['services']['catalog']

    if 'use_db' in myconfig and myconfig['use_db']:
        use_db = True
    else:
        use_db = False

    if not use_db:
        if not myconfig['data_volume']:
            raise Exception("must configure catalog to either use_db=True or set a local data_volume=</path/to/data_volume/>")

        try:
            if not os.path.exists(myconfig['data_volume']):
                os.makedirs(myconfig['data_volume'])
            data_volume = myconfig['data_volume']

        except Exception as err:
            raise err

    archive_initialized = True
    return(True)

def put_document(userId, bucket, archiveId, data):
    payload = {'document': data}
    return(put(userId, bucket, archiveId, payload))

def put(userId, bucket, archiveid, data):
    global archive_initialized, data_volume, use_db

    if not archive_initialized:
        raise Exception("archive not initialized")

    if use_db:
        try:
            with db.session_scope() as dbsession:
                blarg = {'jsondata':json.dumps(data)}
                db_archivedocument.add(userId, bucket, archiveid, archiveid+".json", blarg, session=dbsession)
        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err
    else:
        try:
            if not os.path.exists(os.path.join(data_volume, bucket)):
                os.makedirs(os.path.join(data_volume, bucket))

            with open(os.path.join(data_volume, bucket, archiveid+".json"), 'w') as OFH:
                OFH.write(json.dumps(data))

        except Exception as err:
            logger.debug("cannot put data: exception - " + str(err))
            raise err
    
    return(True)

def get_document(userId, bucket, archiveId):
    archive_document = get(userId, bucket, archiveId)
    ret = archive_document['document']
    return(ret)

def get(userId, bucket, archiveid):
    global archive_initialized, data_volume, use_db

    if not archive_initialized:
        raise Exception("archive not initialized")

    ret = {}

    if use_db:
        try:
            with db.session_scope() as dbsession:
                result = db_archivedocument.get(userId, bucket, archiveid, session=dbsession)
            if result and 'jsondata' in result:
                ret = json.loads(result['jsondata'])
                del result
            else:
                raise Exception("no archive record JSON data found in DB")
        except Exception as err:
            logger.debug("cannot get data: exception - " + str(err))
            raise err
    else:
        try:
            with open(os.path.join(data_volume, bucket, archiveid+".json"), 'r') as FH:
                ret = json.loads(FH.read())
        except Exception as err:
            logger.debug("cannot get data: exception - " + str(err))
            raise err

    return(ret)

def delete(userId, bucket, archiveid):
    global archive_initialized, data_volume, use_db

    if not archive_initialized:
        raise Exception("archive not initialized")

    if use_db:
        try:
            with db.session_scope() as dbsession:
                rc = db_archivedocument.delete(userId, bucket, archiveid, session=dbsession)
                if not rc:
                    raise Exception("failed to delete")
        except Exception as err:
            raise err
    else:
        try:
            if os.path.exists(os.path.join(data_volume, bucket, archiveid+".json")):
                os.remove(os.path.join(data_volume, bucket, archiveid+".json"))
        except Exception as err:            
            raise err

    return(True)
