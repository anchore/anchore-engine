import time
import json

from sqlalchemy import Column, Integer, String, BigInteger, DateTime

import anchore_engine.db.entities.common
from distutils.version import StrictVersion

try:
    from anchore_engine.subsys import logger
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log
except:
    import logging
    logger = logging.getLogger(__name__)
    log = logger

upgrade_enabled = True

def get_versions():
    code_versions = {}
    db_versions = {}
    
    from anchore_engine import version

    code_versions['service_version'] = version.version
    code_versions['db_version'] = version.db_version

    #code_versions = anchore_engine.configuration.localconfig.get_versions()
    try:
        from anchore_engine.db import db_anchore, session_scope

        db_versions = {}
        with session_scope() as dbsession:
            db_versions = db_anchore.get(session=dbsession)
    except Exception as err:
        raise Exception("Cannot find existing/populated anchore DB tables in connected database - has anchore-engine initialized this DB?\n\nDB - exception: " + str(err))

    return(code_versions, db_versions)

def do_upgrade_success(db_versions, code_versions):
    from anchore_engine.db import db_anchore, session_scope

    with session_scope() as dbsession:
        db_anchore.add(code_versions['service_version'], code_versions['db_version'], code_versions, session=dbsession)

    return(True)

def do_upgrade(inplace, incode):
    global upgrade_enabled, upgrade_functions

    engine = anchore_engine.db.entities.common.get_engine()

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
                            log.exception('Upgrade function {} raised an error. Failing upgrade.'.format(fn.__name__))
                            raise e

                    db_current = db_to

    if inplace['service_version'] != incode['service_version']:
        print ("upgrading service: from=" + str(inplace['service_version']) + " to=" + str(incode['service_version']))

    ret = True
    return (ret)

### Individual upgrade routines - be sure to add to the function map at the end of this module if adding a new routine here

def db_upgrade_001_002():
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db import db_anchore, db_users, db_registries, db_policybundle, db_catalog_image

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

    from anchore_engine.db import db_anchore, db_users, db_registries, db_policybundle, db_catalog_image, db_archivedocument
    import anchore_engine.services.common
    import anchore_engine.subsys.archive

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

def db_upgrade_005_006():
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


