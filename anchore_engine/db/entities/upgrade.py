import json
import time
from sqlalchemy import Column, Integer, String, BigInteger, DateTime

import anchore_engine.db.entities.common
from anchore_engine.db.entities.common import StringJSON
import anchore_engine.common.helpers
from anchore_engine.db.entities.exceptions import is_table_not_found
from distutils.version import StrictVersion
from contextlib import contextmanager

try:
    from anchore_engine.subsys import logger, identities
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log
except:
    import logging
    logger = logging.getLogger(__name__)
    log = logger

upgrade_enabled = True

# Set at module level for any db module that needs db upgrade ability
my_module_upgrade_id = 1

def do_db_compatibility_check():
    required_pg_version = (9,6)

    try:
        engine = anchore_engine.db.entities.common.get_engine()
        if engine.dialect.server_version_info >= required_pg_version:
            return(True)
        else:
            raise Exception("discovered db version {} is not >= required db version {}".format(engine.dialect.server_version_info, required_pg_version))
    except Exception as err:
        raise err

    raise Exception("database compatibility could not be performed")

def do_db_post_actions(localconfig=None):
    return


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
def upgrade_context(lock_id):
    """
    Provides a context for upgrades including a lock on the db to ensure only one upgrade process at a time doing checks.

    Use a postgresql application lock to block schema updates and serialize checks
    :param lock_id: the lock id (int) for the lock to acquire
    :return:
    """
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db.db_locks import db_application_lock, application_lock_ids

    with db_application_lock(engine, (application_lock_ids['upgrade']['namespace'], lock_id)):
        versions = get_versions()
        yield versions

def do_create_tables(specific_tables=None):
    print ("Creating DB Tables")
    from anchore_engine.db.entities.common import Base, do_create

    try:
        with upgrade_context(my_module_upgrade_id) as ctx:
            do_create(specific_tables=specific_tables, base=Base)
    except Exception as err:
        raise err
    print ("DB Tables created")
    return(True)

def do_db_bootstrap(localconfig=None, db_versions=None, code_versions=None):
    from anchore_engine.db import session_scope

    with upgrade_context(my_module_upgrade_id) as ctx:
        with session_scope() as session:
            try:
                initializer = identities.IdentityBootstrapper(identities.IdentityManager, session)
                initializer.initialize_system_identities()
            except Exception as err:
                logger.exception('Error initializing system credentials on db bootstrap')
                raise Exception("Initialization failed: could not initialize system credentials - exception: " + str(err))

        do_version_update(db_versions, code_versions)

def run_upgrade():
    """
    Entry point for upgrades (idempotent). If already upgraded, this is a no-op. If database is un-initialized.
    Will raise exception on failure and return bool. True = upgrade completed, False = no upgrade necessary.

    :return: True if upgrade executed, False if success, but no upgrade needed.
    """
    with upgrade_context(my_module_upgrade_id) as ctx:
        code_versions = ctx[0]
        db_versions = ctx[1]

        code_db_version = ctx[0].get('db_version', None)
        running_db_version = ctx[1].get('db_version', None)

        if not code_db_version:
            raise Exception("cannot get code version (code_db_version={} running_db_version={})".format(code_db_version, running_db_version))
        elif code_db_version and running_db_version is None:
            print("Detected no running db version, indicating db is not initialized but is connected. No upgrade necessary. Exiting normally.")
            ecode = 0
        elif code_db_version == running_db_version:
            print("Detected anchore-engine version {} and running DB version {} match, nothing to do.".format(code_db_version, running_db_version))
        else:
            print("Detected anchore-engine version {}, running DB version {}.".format(code_db_version, running_db_version))
            print("Performing upgrade.")
            try:
                rc = do_create_tables()
                if rc:
                    print("Table create success.")
                else:
                    raise Exception("Failure while creating tables.")

                # perform the upgrade logic here
                rc = do_upgrade(db_versions, code_versions)
                if rc:
                    # if successful upgrade, set the DB values to the incode values
                    rc = do_version_update(db_versions, code_versions)
                    print("Upgrade success.")
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
        print(("Upgrading DB: from=" + str(inplace['db_version']) + " to=" + str(incode['db_version'])))

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
                    print(("Executing upgrade functions for version {} to {}".format(db_from, db_to)))
                    for fn in functions_to_run:
                        try:
                            print(("Executing upgrade function: {}".format(fn.__name__)))
                            fn()
                        except Exception as e:
                            log.err('Upgrade function {} raised an error. Failing upgrade.'.format(fn.__name__))
                            raise e

                    db_current = db_to

    if inplace['service_version'] != incode['service_version']:
        print(("upgrading service: from=" + str(inplace['service_version']) + " to=" + str(incode['service_version'])))

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
    import anchore_engine.common

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
                anchore_engine.common.helpers.update_image_record_with_analysis_data(image_record, image_data)
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
    from anchore_engine.subsys import archive
    from anchore_engine.subsys.archive import operations
    from anchore_engine.configuration import localconfig

    config = localconfig.get_config()
    archive.initialize(config.get('services', {}).get('catalog', {}))
    client = operations.get_archive().primary_client

    session_counter = 0
    max_pending_session_size = 10000

    with session_scope() as db_session:
        for doc in db_session.query(ArchiveDocument.userId, ArchiveDocument.bucket, ArchiveDocument.archiveId, ArchiveDocument.documentName, ArchiveDocument.created_at, ArchiveDocument.last_updated, ArchiveDocument.record_state_key, ArchiveDocument.record_state_val):
            meta = ArchiveMetadata(userId=doc[0],
                                   bucket=doc[1],
                                   archiveId=doc[2],
                                   documentName=doc[3],
                                   is_compressed=False,
                                   document_metadata=None,
                                   content_url=client.uri_for(userId=doc[0], bucket=doc[1], key=doc[2]),
                                   created_at=doc[4],
                                   last_updated=doc[5],
                                   record_state_key=doc[6],
                                   record_state_val=doc[6]
                                   )

            db_session.add(meta)

            session_counter += 1

            if session_counter >= max_pending_session_size:
                db_session.flush()
                session_counter = 0


def fixed_artifact_upgrade_005_006():
    """
    Upgrade the feed_data_vulnerabilities_fixed_artifacts schema with new columns and fill in the defaults

    """
    from anchore_engine.db import session_scope
    from sqlalchemy import Column, Text, Boolean

    engine = anchore_engine.db.entities.common.get_engine()

    table_name = 'feed_data_vulnerabilities_fixed_artifacts'
    vna = 'vendor_no_advisory'
    newcolumns = [
        Column(vna, Boolean, primary_key=False),
        Column('fix_metadata', Text, primary_key=False)
    ]

    for column in newcolumns:
        try:
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))
        except Exception as e:
            raise Exception('failed to perform DB upgrade on {} adding column {} - exception: {}'.format(table_name, column.name, str(e)))

    try:
        engine.execute('UPDATE %s SET %s = FALSE WHERE %s IS NULL' % (table_name, vna, vna))
    except Exception as e:
        raise Exception('failed to perform DB upgrade on {} setting default value for column {} - exception: {}'.format(table_name, vna, str(e)))


def db_upgrade_005_006():
    queue_data_upgrades_005_006()
    archive_data_upgrade_005_006()
    fixed_artifact_upgrade_005_006()

def catalog_image_upgrades_006_007():
    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            'table_name': 'catalog_image',
            'columns': [
                Column('analyzed_at', Integer, primary_key=False)
            ]
        },
        {
            'table_name': 'catalog_image_docker',
            'columns': [
                Column('tag_detected_at', Integer, primary_key=False)
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
                log.err('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))
                raise Exception('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))

    try:
        engine.execute("UPDATE catalog_image SET analyzed_at=last_updated WHERE analyzed_at IS NULL AND analysis_status='analyzed'")
    except Exception as e:
        raise Exception('failed to perform DB upgrade on catalog_image setting default value for column analyzed_at - exception: {}'.format(str(e)))

    try:
        engine.execute("UPDATE catalog_image_docker SET tag_detected_at=created_at WHERE tag_detected_at IS NULL")
    except Exception as e:
        raise Exception('failed to perform DB upgrade on catalog_image_docker setting default value for column tag_detected_at - exception: {}'.format(str(e)))


def user_account_upgrades_007_008():
    logger.info('Upgrading user accounts for multi-user support')

    from anchore_engine.db import session_scope, legacy_db_users
    from anchore_engine.subsys.identities import manager_factory, AccountStates
    from anchore_engine.configuration.localconfig import SYSTEM_ACCOUNT_NAME, ADMIN_ACCOUNT_NAME

    with session_scope() as session:
        mgr = manager_factory.for_session(session)
        for user in legacy_db_users.get_all():

            if user['userId'] == ADMIN_ACCOUNT_NAME:
                account_type = identities.AccountTypes.admin
            elif user['userId'] == SYSTEM_ACCOUNT_NAME:
                account_type = identities.AccountTypes.service
            else:
                account_type = identities.AccountTypes.user

            logger.info('Migrating user: {} to new account with name {}, type {}, is_active {}'.format(user['userId'], user['userId'], account_type, user['active']))
            accnt = mgr.create_account(account_name=user['userId'], email=user['email'], account_type=account_type)
            if not user['active']:
                mgr.update_account_state(accnt['name'], AccountStates.disabled)

            logger.info('Creating new user record in new account {} with username {}'.format(user['userId'], user['userId']))
            mgr.create_user(account_name=user['userId'], username=user['userId'], password=user['password'])

            logger.info('Deleting old user record')
            legacy_db_users.delete(user['userId'], session)

    logger.info('User account upgrade complete')


def db_upgrade_006_007():
    catalog_image_upgrades_006_007()

def db_upgrade_007_008():
    catalog_upgrade_007_008()
    policy_engine_packages_upgrade_007_008()
    user_account_upgrades_007_008()

def catalog_upgrade_007_008():
    from anchore_engine.db import session_scope, CatalogImage

    log.err("performing catalog table upgrades")
    engine = anchore_engine.db.entities.common.get_engine()
    new_columns = [
        {
            'table_name': 'catalog_image',
            'columns': [
                Column('parentDigest', String()),
            ]
        },
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table['columns']:
            log.err("creating new column ({}) in table ({})".format(column.name, table.get('table_name', "")))
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table['table_name'], cn, ct))
            except Exception as e:
                log.err('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))
                raise Exception('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))
        
def policy_engine_packages_upgrade_007_008():
    from anchore_engine.db import session_scope, ImagePackage, ImageNpm, ImageGem, Image
    if True:
        engine = anchore_engine.db.entities.common.get_engine()

        file_path_length = 512
        hash_length = 80

        new_columns = [
            {
                'table_name': 'image_packages',
                'columns': [
                    Column('pkg_path', String(file_path_length), primary_key=True),
                    Column('pkg_path_hash', String(hash_length)),
                    Column('metadata_json', StringJSON),
                ]
            },
            {
                'table_name': 'image_package_vulnerabilities',
                'columns': [
                    Column('pkg_path', String(file_path_length), primary_key=True),
                ]
            },
            {
                'table_name': 'image_package_db_entries',
                'columns': [
                    Column('pkg_path', String(file_path_length), primary_key=True),
                ]
            }
        ]

        log.err("creating new table columns")
        for table in new_columns:
            for column in table['columns']:
                log.err("creating new column ({}) in table ({})".format(column.name, table.get('table_name', "")))
                try:
                    cn = column.compile(dialect=engine.dialect)
                    ct = column.type.compile(engine.dialect)
                    engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table['table_name'], cn, ct))
                except Exception as e:
                    log.err('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))
                    raise Exception('failed to perform DB upgrade on {} adding column - exception: {}'.format(table, str(e)))


        # populate the new columns
        log.err("updating new column (pkg_path) - this may take a while")
        for table in ['image_packages', 'image_package_vulnerabilities']:
            log.err("updating table ({}) column (pkg_path)".format(table))
            done = False
            while not done:
                startts = time.time()
                rc = engine.execute("UPDATE {} set pkg_path='pkgdb' where pkg_path is null".format(table))
                log.err("updated {} records in {} (time={}), performing next range".format(rc.rowcount, table, time.time() - startts))
                done=True


        with session_scope() as dbsession:
            db_image_ids = dbsession.query(Image.id).distinct().all()

        total_records = len(db_image_ids)
        record_count = 0
        for record in db_image_ids:
            db_image_id = record[0]
            startts = time.time()
            rc = engine.execute("UPDATE image_package_db_entries set pkg_path='pkgdb' where image_id='{}' and pkg_path is null".format(db_image_id))
            record_count = record_count + 1
            log.err("updated {} image ({} / {}) in {} (time={}), performing next image update".format(db_image_id, record_count, total_records, 'image_package_db_entries', time.time() - startts))

        exec_commands = [
            'ALTER TABLE image_package_vulnerabilities DROP CONSTRAINT IF EXISTS image_package_vulnerabilities_pkg_image_id_fkey',
            'ALTER TABLE image_package_db_entries DROP CONSTRAINT IF EXISTS image_package_db_entries_image_id_fkey',
            'ALTER TABLE image_packages DROP CONSTRAINT IF EXISTS image_packages_pkey',
            'ALTER TABLE image_package_db_entries DROP CONSTRAINT IF EXISTS image_package_db_entries_pkey',
            'ALTER TABLE image_package_vulnerabilities DROP CONSTRAINT IF EXISTS image_package_vulnerabilities_pkey',
        ]

        log.err("dropping primary key / foreign key relationships for new column")
        cmdcount = 1
        for command in exec_commands:
            log.err("running update operation {} of {}: {}".format(cmdcount, len(exec_commands), command))
            engine.execute(command)
            cmdcount = cmdcount + 1

        exec_commands = [
            'ALTER TABLE image_packages ADD PRIMARY KEY (image_id,image_user_id,name,version,pkg_type,arch,pkg_path)',
            'ALTER TABLE image_package_vulnerabilities ADD PRIMARY KEY (pkg_user_id,pkg_image_id,pkg_name,pkg_version,pkg_type,pkg_arch,vulnerability_id,pkg_path)',
            'ALTER TABLE image_package_db_entries ADD PRIMARY KEY (image_id, image_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path,file_path)',
            'ALTER TABLE image_package_vulnerabilities ADD CONSTRAINT image_package_vulnerabilities_pkg_image_id_fkey FOREIGN KEY (pkg_image_id, pkg_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path) REFERENCES image_packages (image_id, image_user_id, name, version, pkg_type, arch, pkg_path) MATCH SIMPLE',
            'ALTER TABLE image_package_db_entries ADD CONSTRAINT image_package_db_entries_image_id_fkey FOREIGN KEY (image_id, image_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path) REFERENCES image_packages (image_id, image_user_id, name, version, pkg_type, arch, pkg_path) MATCH SIMPLE',
        ]

        log.err("updating primary key / foreign key relationships for new column - this may take a while")
        cmdcount = 1
        for command in exec_commands:
            log.err("running update operation {} of {}: {}".format(cmdcount, len(exec_commands), command))
            engine.execute(command)
            cmdcount = cmdcount + 1


        log.err("converting ImageNpm and ImageGem records into ImagePackage records - this may take a while")
        # migrate ImageNpm and ImageGem records into ImagePackage records
        with session_scope() as dbsession:
            db_npms = dbsession.query(ImageNpm)
            total_npms = dbsession.query(ImageNpm).count()
            db_gems = dbsession.query(ImageGem)
            total_gems = dbsession.query(ImageGem).count()

        npms = []
        chunk_size = 8192
        record_count = 0
        try:
            for n in db_npms:
                np = ImagePackage()

                # primary keys
                np.name = n.name
                if len(n.versions_json):
                    version = n.versions_json[0]
                else:
                    version = "N/A"
                np.version = version
                np.pkg_type = 'npm'
                np.arch = 'N/A'
                np.image_user_id = n.image_user_id
                np.image_id = n.image_id
                np.pkg_path = n.path

                # other
                np.pkg_path_hash = n.path_hash
                np.distro_name = 'npm'
                np.distro_version = 'N/A'
                np.like_distro = 'npm'
                np.fullversion = np.version
                np.license = ' '.join(n.licenses_json)
                np.origin = ' '.join(n.origins_json)
                fullname = np.name
                np.normalized_src_pkg = fullname
                np.src_pkg = fullname
                npms.append(np)
                if len(npms) >= chunk_size:
                    startts = time.time()
                    try:
                        with session_scope() as dbsession:
                            dbsession.bulk_save_objects(npms)
                            record_count = record_count + chunk_size
                    except:
                        log.err("skipping duplicates")
                        record_count = record_count + chunk_size
                    log.err("merged {} / {} npm records (time={}), performing next range".format(record_count, total_npms, time.time() - startts))

                    npms = []

            if len(npms):
                startts = time.time()
                try:
                    with session_scope() as dbsession:
                        dbsession.bulk_save_objects(npms)
                        record_count = record_count + len(npms)
                except:
                    log.err("skipping duplicates")
                    record_count = record_count + len(npms)
                log.err("final merged {} / {} npm records (time={})".format(record_count, total_npms, time.time() - startts))

        except Exception as err:
            raise err

        gems = []
        chunk_size = 8192
        record_count = 0
        try:
            for n in db_gems:

                np = ImagePackage()

                # primary keys
                np.name = n.name
                if len(n.versions_json):
                    version = n.versions_json[0]
                else:
                    version = "N/A"
                np.version = version
                np.pkg_type = 'gem'
                np.arch = 'N/A'
                np.image_user_id = n.image_user_id
                np.image_id = n.image_id
                np.pkg_path = n.path

                # other
                np.pkg_path_hash = n.path_hash
                np.distro_name = 'gem'
                np.distro_version = 'N/A'
                np.like_distro = 'gem'
                np.fullversion = np.version
                np.license = ' '.join(n.licenses_json)
                np.origin = ' '.join(n.origins_json)
                fullname = np.name
                np.normalized_src_pkg = fullname
                np.src_pkg = fullname
                gems.append(np)
                if len(gems) >= chunk_size:
                    startts = time.time()
                    try:
                        with session_scope() as dbsession:
                            dbsession.bulk_save_objects(gems)
                            record_count = record_count + chunk_size
                    except:
                        log.err("skipping duplicates")
                        record_count = record_count + chunk_size
                    log.err("merged {} / {} gem records (time={}), performing next range".format(record_count, total_gems, time.time() - startts))

                    gems = []

            if len(gems):
                startts = time.time()
                try:
                    with session_scope() as dbsession:
                        dbsession.bulk_save_objects(gems)
                        record_count = record_count + len(gems)
                except:
                    log.err("skipping duplicates")
                    record_count = record_count + len(gems)
                log.err("final merged {} / {} gem records (time={})".format(record_count, total_gems, time.time() - startts))

        except Exception as err:
            raise err


# Global upgrade definitions. For a given version these will be executed in order of definition here
# If multiple functions are defined for a version pair, they will be executed in order.
# If any function raises and exception, the upgrade is failed and halted.
upgrade_functions = (
    (('0.0.1', '0.0.2'), [ db_upgrade_001_002 ]),
    (('0.0.2', '0.0.3'), [ db_upgrade_002_003 ]),
    (('0.0.3', '0.0.4'), [ db_upgrade_003_004 ]),
    (('0.0.4', '0.0.5'), [ db_upgrade_004_005 ]),
    (('0.0.5', '0.0.6'), [ db_upgrade_005_006 ]),
    (('0.0.6', '0.0.7'), [ db_upgrade_006_007 ]),
    (('0.0.7', '0.0.8'), [ db_upgrade_007_008 ])
)
