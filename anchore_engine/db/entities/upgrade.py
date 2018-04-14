import json
import hashlib
import uuid
import zlib
from sqlalchemy import Column, Integer, String, BigInteger, DateTime

import anchore_engine.db.entities.common
from anchore_engine.db.entities.exceptions import is_table_not_found, TableNotFoundError
from distutils.version import StrictVersion
from contextlib import contextmanager


try:
    from anchore_engine.subsys import logger
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log
except:
    import logging
    logger = logging.getLogger(__name__)
    log = logger

upgrade_enabled = True
#my_module_upgrade_id = 1


def get_versions():
    code_versions = {}
    db_versions = {}
    
    from anchore_engine import version

    code_versions['service_version'] = version.version
    code_versions['db_version'] = version.db_version

    try:
        from anchore_engine.db import db_anchore, session_scope
        with session_scope() as dbsession:
            db_versions = db_anchore.get(session=dbsession)

    except Exception as err:
        if is_table_not_found(err):
            logger.info("anchore table not found")
            #raise TableNotFoundError('anchore table not found')
        else:
            raise Exception("Cannot find existing/populated anchore DB tables in connected database - has anchore-engine initialized this DB?\n\nDB - exception: " + str(err))

    return(code_versions, db_versions)

def do_version_update(db_versions, code_versions):
    from anchore_engine.db import db_anchore, session_scope

    with session_scope() as dbsession:
        db_anchore.add(code_versions['service_version'], code_versions['db_version'], code_versions, session=dbsession)

    return(True)


@contextmanager
def upgrade_context():
    """
    Provides a context for upgrades including a lock on the db to ensure only one upgrade process at a time doing checks.

    Use a postgresql application lock to block schema updates and serialize checks
    :param lock_id: the lock id (int) for the lock to acquire
    :return:
    """
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db.db_locks import db_application_lock, application_lock_ids

    with db_application_lock(engine, (application_lock_ids['upgrade']['namespace'], application_lock_ids['upgrade']['ids']['db_upgrade'])):
        versions = get_versions()
        yield versions

def do_create_tables(specific_tables=None):
    print ("Creating DB Tables")
    try:
        with upgrade_context(my_module_upgrade_id) as ctx:
            anchore_engine.db.entities.common.do_create(specific_tables)
    except Exception as err:
        raise err
    print ("DB Tables created")
    return(True)

def do_db_bootstrap(localconfig=None):
    with upgrade_context(my_module_upgrade_id) as ctx:

        from anchore_engine.db import db_users, session_scope
        with session_scope() as dbsession:
            # system user
            try:
                system_user_record = db_users.get('anchore-system', session=dbsession)
                if not system_user_record:
                    rc = db_users.add('anchore-system', str(uuid.uuid4()), {'active': True}, session=dbsession)
                else:
                    db_users.update(system_user_record['userId'], system_user_record['password'], {'active': True}, session=dbsession)

            except Exception as err:
                raise Exception("Initialization failed: could not fetch/add anchore-system user from/to DB - exception: " + str(err))

            if localconfig:
                try:
                    for userId in localconfig['credentials']['users']:
                        if not localconfig['credentials']['users'][userId]:
                            localconfig['credentials']['users'][userId] = {}

                        cuser = localconfig['credentials']['users'][userId]

                        password = cuser.pop('password', None)
                        email = cuser.pop('email', None)
                        if password and email:
                            db_users.add(userId, password, {'email': email, 'active': True}, session=dbsession)
                        else:
                            raise Exception("user defined but has empty password/email: " + str(userId))

                    user_records = db_users.get_all(session=dbsession)
                    for user_record in user_records:
                        if user_record['userId'] == 'anchore-system':
                            continue
                        if user_record['userId'] not in localconfig['credentials']['users']:
                            logger.info("flagging user '"+str(user_record['userId']) + "' as inactive (in DB, not in configuration)")
                            db_users.update(user_record['userId'], user_record['password'], {'active': False}, session=dbsession)

                except Exception as err:
                    raise Exception("Initialization failed: could not add users from config into DB - exception: " + str(err))

def run_upgrade():
    """
    Entry point for upgrades (idempotent). If already upgraded, this is a no-op. If database is un-initialized.
    Will raise exception on failure and return bool. True = upgrade completed, False = no upgrade necessary.

    :return: True if upgrade executed, False if success, but no upgrade needed.
    """

    with upgrade_context() as ctx:
        code_versions = ctx[0]
        db_versions = ctx[1]

        code_db_version = ctx[0].get('db_version', None)
        running_db_version = ctx[1].get('db_version', None)

        if not code_db_version:
            raise Exception("cannot get code version (code_db_version={} running_db_version={})".format(code_db_version, running_db_version))
        elif code_db_version and running_db_version is None:
            print "Detected no running db version, indicating db is not initialized but is connected. No upgrade necessary. Exiting normally."
            ecode = 0
        elif code_db_version == running_db_version:
            print "Detected anchore-engine version {} and running DB version {} match, nothing to do.".format(code_db_version, running_db_version)
        else:
            print "Detected anchore-engine version {}, running DB version {}.".format(code_db_version, running_db_version)
            print "Performing upgrade."
            try:
                rc = do_create_tables()
                if rc:
                    print "Table create success."
                else:
                    raise Exception("Failure while creating tables.")

                # perform the upgrade logic here
                rc = do_upgrade(db_versions, code_versions)
                if rc:
                    # if successful upgrade, set the DB values to the incode values
                    rc = do_version_update(db_versions, code_versions)
                    print "Upgrade success."
                    return rc
                else:
                    raise Exception("Upgrade routine from module returned false, please check your DB/environment and try again")
            except Exception as err:
                raise err

def do_upgrade(inplace, incode):
    global upgrade_enabled, upgrade_functions

    if StrictVersion(inplace['db_version']) > StrictVersion(incode['db_version']):
        raise Exception("DB downgrade not supported")

    if inplace['db_version'] != incode['db_version']:
        print ("Upgrading DB: from=" + str(inplace['db_version']) + " to=" + str(incode['db_version']))

        if upgrade_enabled:
            db_current = inplace['db_version']
            db_target = incode['db_version']

            for version_tuple, functions_to_run in upgrade_functions:
                db_from = version_tuple[0]
                db_to = version_tuple[1]

                # finish if we've reached the target version
                if StrictVersion(db_current) >= StrictVersion(db_target):
                    # done
                    break
                elif StrictVersion(db_to) <= StrictVersion(db_current):
                    # Upgrade code is for older version, skip it.
                    continue
                else:
                    print("Executing upgrade functions for version {} to {}".format(db_from, db_to))
                    for fn in functions_to_run:
                        try:
                            print("Executing upgrade function: {}".format(fn.__name__))
                            fn()
                        except Exception as e:
                            log.err('Upgrade function {} raised an error. Failing upgrade.'.format(fn.__name__))
                            raise e

                    db_current = db_to

    if inplace['service_version'] != incode['service_version']:
        print ("upgrading service: from=" + str(inplace['service_version']) + " to=" + str(incode['service_version']))

    ret = True
    return (ret)

### Individual upgrade routines - be sure to add to the function map at the end of this module if adding a new routine here

def db_upgrade_001_002():
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db import db_registries, db_policybundle, session_scope

    try:
        table_name = 'registries'
        column = Column('registry_type', String, primary_key=False)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))

        with session_scope() as dbsession:
            registry_records = db_registries.get_all(session=dbsession)
            for registry_record in registry_records:
                try:
                    if not registry_record['registry_type']:
                        registry_record['registry_type'] = 'docker_v2'
                        db_registries.update_record(registry_record, session=dbsession)
                except Exception as err:
                    pass
    except Exception as err:
        raise Exception("failed to perform DB registry table upgrade - exception: " + str(err))

    try:
        table_name = 'policy_bundle'
        column = Column('policy_source', String, primary_key=False)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))

        with session_scope() as dbsession:
            policy_records = db_policybundle.get_all(session=dbsession)
            for policy_record in policy_records:
                try:
                    if not policy_record['policy_source']:
                        policy_record['policy_source'] = 'local'
                        db_policybundle.update_record(policy_record, session=dbsession)
                except Exception as err:
                    pass

    except Exception as err:
        raise Exception("failed to perform DB policy_bundle table upgrade - exception: " + str(err))

    return (True)


def db_upgrade_002_003():
    engine = anchore_engine.db.entities.common.get_engine()

    try:
        table_name = 'images'
        column = Column('size', BigInteger)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ALTER COLUMN %s TYPE %s' % (table_name, cn, ct))
    except Exception as e:
        raise Exception('failed to perform DB upgrade on images.size field change from int to bigint - exception: {}'.format(str(e)))

    try:
        table_name = 'feed_data_gem_packages'
        column = Column('id', BigInteger)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute('ALTER TABLE %s ALTER COLUMN %s TYPE %s' % (table_name, cn, ct))
    except Exception as e:
        raise Exception('failed to perform DB upgrade on feed_data_gem_packages.id field change from int to bigint - exception: {}'.format(str(e)))

    return True

def db_upgrade_003_004():
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db import db_catalog_image, db_archivedocument, session_scope
    import anchore_engine.services.common

    newcolumns = [
        Column('arch', String, primary_key=False),
        Column('distro', String, primary_key=False),
        Column('distro_version', String, primary_key=False),
        Column('dockerfile_mode', String, primary_key=False),
        Column('image_size', BigInteger, primary_key=False),
        Column('layer_count', Integer, primary_key=False)
    ]
    for column in newcolumns:
        try:
            table_name = 'catalog_image'
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))
        except Exception as e:
            log.err('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))
            raise Exception('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))

    with session_scope() as dbsession:
        image_records = db_catalog_image.get_all(session=dbsession)

    for image_record in image_records:
        userId = image_record['userId']
        imageDigest = image_record['imageDigest']

        log.err("upgrade: processing image " + str(imageDigest) + " : " + str(userId))
        try:

            # get the image analysis data from archive
            image_data = None
            with session_scope() as dbsession:
                result = db_archivedocument.get(userId, 'analysis_data', imageDigest, session=dbsession)
            if result and 'jsondata' in result:
                image_data = json.loads(result['jsondata'])['document']
                
            if image_data:
                # update the record and store
                anchore_engine.services.common.update_image_record_with_analysis_data(image_record, image_data)
                with session_scope() as dbsession:
                    db_catalog_image.update_record(image_record, session=dbsession)
            else:
                raise Exception("upgrade: no analysis data found in archive for image: " + str(imageDigest))
        except Exception as err:
            log.err("upgrade: failed to populate new columns with existing data for image (" + str(imageDigest) + "), record may be incomplete: " + str(err))

    return True

def db_upgrade_004_005():
    engine = anchore_engine.db.entities.common.get_engine()
    from sqlalchemy import Column, String

    newcolumns = [
        Column('annotations', String, primary_key=False),
    ]
    for column in newcolumns:
        try:
            table_name = 'catalog_image'
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))
        except Exception as e:
            log.err('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))
            raise Exception('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))

def queue_data_upgrades_005_006():
    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {'table_name': 'queuemeta',
         'columns': [
             Column('max_outstanding_messages', Integer, primary_key=False, default=0),
             Column('visibility_timeout', Integer, primary_key=False, default=0)
         ]
         },
        {'table_name': 'queue',
         'columns': [
             Column('receipt_handle', String, primary_key=False),
             Column('visible_at', DateTime, primary_key=False)

         ]
         }
    ]

    for table in new_columns:
        for column in table['columns']:
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table['table_name'], cn, ct))
            except Exception as e:
                log.err('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))
                raise Exception('failed to perform DB upgrade on catalog_image adding column - exception: {}'.format(str(e)))


def archive_data_upgrade_005_006():
    """
    Upgrade the document archive data schema and move the data appropriately.
    Assumes both tables are in place (archive_document, archive_document_reference, object_storage)

    :return:
    """

    from anchore_engine.db import ArchiveDocument, session_scope, ArchiveMetadata
    import anchore_engine.subsys.object_store

    # TODO: which client? Look at local config or as provided by the upgrade operation explicitly
    client = anchore_engine.subsys.object_store.init_driver(configuration={'name': 'db', 'config': {}})

    with session_scope() as db_session:
        for doc in db_session.query(ArchiveDocument):
            meta = ArchiveMetadata(userId=doc.userId,
                                   bucket=doc.bucket,
                                   archiveId=doc.archiveId,
                                   documentName=doc.documentName,
                                   is_compressed=False,
                                   document_metadata=None,
                                   content_url=client.uri_for(userId=doc.userId, bucket=doc.bucket, key=doc.archiveId),
                                   created_at=doc.created_at,
                                   last_updated=doc.last_updated,
                                   record_state_key=doc.record_state_key,
                                   record_state_val=doc.record_state_val
                                   )

            if doc.jsondata is not None:
                meta.size = len(doc.jsondata)
                meta.digest = hashlib.md5(doc.jsondata).hexdigest()
            else:
                pass
                # TODO: get info on digest/size from fs driver (the only other option from db prior to this version)

            db_session.add(meta)
            db_session.flush()

def db_upgrade_005_006():
    queue_data_upgrades_005_006()
    archive_data_upgrade_005_006()


# Global upgrade definitions. For a given version these will be executed in order of definition here
# If multiple functions are defined for a version pair, they will be executed in order.
# If any function raises and exception, the upgrade is failed and halted.
upgrade_functions = (
    (('0.0.1', '0.0.2'), [ db_upgrade_001_002 ]),
    (('0.0.2', '0.0.3'), [ db_upgrade_002_003 ]),
    (('0.0.3', '0.0.4'), [ db_upgrade_003_004 ]),
    (('0.0.4', '0.0.5'), [ db_upgrade_004_005 ]),
    (('0.0.5', '0.0.6'), [ db_upgrade_005_006 ])
)


