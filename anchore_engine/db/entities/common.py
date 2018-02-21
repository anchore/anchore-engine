"""
Common functions and variables for all entity types including some bootstrap and init functions
"""

import json
import uuid
import time
import traceback
from contextlib import contextmanager
from distutils.version import StrictVersion

import sqlalchemy
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import datetime

try:
    from anchore_engine.subsys import logger
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log
except:
    import logging
    logger = logging.getLogger(__name__)
    log = logger

Session = None  # Standard session maker
ThreadLocalSession = None  # Separate thread-local session maker
engine = None
Base = declarative_base()
upgrade_enabled = True


class UtilMixin(object):
    """
    Common mixin class for functions that all db entities (or most) should have
    """

    def update(self, inobj):
        for a in inobj.keys():
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def to_json(self):
        """
        Returns json-encoded string representation of the object's members. If datetime.datetime object is found, converts it to iso8601 format

        NOTE: this is a very simple implementation that assumes members are simple types. If an object has complex types as member, that
        class should override this function with an impl that serializes those types properly for json.

        :return: string
        """
        return dict((key, value if type(value) != datetime.datetime else value.isoformat()) for key, value in vars(self).iteritems() if not key.startswith('_'))

    def to_dict(self):
        """
        Returns a dictionary version of the object. Basically the same as json(), but leaves types unchanged whereas json() does encoding to strings for
        things like datetime objects.

        :return:
        """

        return dict((key, value) for key, value in vars(self).iteritems() if not key.startswith('_'))

    def to_detached(self):
        """
        To be called inside a transaction to create a new entity object with values that are the same as the current object but not part of a transaction and without any
        transaction/session dependencies so can be used outside of session.
        :return: instance(self.__class__)
        """

        obj = self.__class__()
        for name, attr in vars(self).iteritems():
            if not name.startswith('_'):
                setattr(obj, name, attr)

        return obj


def anchore_now():
    """
    Simple epoch time fetcher

    :return: integer unix epoch time
    """
    return (int(time.time()))

def get_entity_tables(entity):
    global Base

    import inspect
            
    entity_names = [x[1].__tablename__ for x in filter(lambda x: inspect.isclass(x[1]) and issubclass(x[1], Base) and x[1] != Base, inspect.getmembers(entity))]
    ftables = filter(lambda x: x.name in entity_names, Base.metadata.sorted_tables)

    return(ftables)

# some DB management funcs
def initialize(localconfig=None, versions=None, bootstrap_db=False, specific_tables=None, bootstrap_users=False):
    """
    Initialize the db for use. Optionally bootstrap it and optionally only for specific entities.

    :param versions:
    :param bootstrap_db:
    :param specific_entities: a list of entity classes to initialize if a subset is desired. Expects a list of classes.
    :return:
    """
    global engine, Session, SerializableSession

    if versions is None:
        versions = {}

    #localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = True
    try:
        db_auth = localconfig['credentials']['database']

        # connect to DB using db_connect from configuration
        db_connect = None
        db_connect_args = {}
        db_pool_size = 10
        db_pool_max_overflow = 20
        if 'db_connect' in db_auth and db_auth['db_connect']:
            db_connect = db_auth['db_connect']
        if 'db_connect_args' in db_auth and db_auth['db_connect_args']:
            db_connect_args = db_auth['db_connect_args']
        if 'db_pool_size' in db_auth:
            db_pool_size = int(db_auth['db_pool_size'])
        if 'db_pool_max_overflow' in db_auth:
            db_pool_max_overflow = int(db_auth['db_pool_max_overflow'])
    except:
        raise Exception(
            "could not locate credentials->database entry from configuration: add 'database' section to 'credentials' section in configuration file")

    db_connect_retry_max = 60
    for count in range(0, db_connect_retry_max):
        try:
            if db_connect:
                try:
                    if db_connect.startswith('sqlite://'):
                        # Special case for testing with sqlite. Not for production use, unit tests only
                        engine = sqlalchemy.create_engine(db_connect, echo=False)
                    else:
                        engine = sqlalchemy.create_engine(db_connect, connect_args=db_connect_args, echo=False,
                                                          pool_size=db_pool_size, max_overflow=db_pool_max_overflow)
                except Exception as err:
                    raise Exception("could not connect to DB - exception: " + str(err))
            else:
                raise Exception(
                    "could not locate db_connect string from configuration: add db_connect parameter to configuration file")

            # set up the global session
            try:
#                SerializableSession = sessionmaker(bind=engine.execution_options(isolation_level='SERIALIZABLE'))
                Session = sessionmaker(bind=engine)
            except Exception as err:
                raise Exception("could not create DB session - exception: " + str(err))

            # set up thread-local session factory
            init_thread_session()

            # create
            try:
                if specific_tables:
                    logger.info('Initializing only a subset of tables as requested: {}'.format(specific_tables))
                    Base.metadata.create_all(engine, tables=specific_tables)
                else:
                    Base.metadata.create_all(engine)
            except Exception as err:
                raise Exception("could not create/re-create DB tables - exception: " + str(err))

            break
        except Exception as err:
            if count > db_connect_retry_max:
                raise Exception("could not establish connection to DB after retry - last exception: " + str(err))
            else:
                log.err("could not connect to db, retrying in 10 seconds - exception: " + str(err))
                time.sleep(5)

    if bootstrap_db:
        from anchore_engine.db import db_anchore, db_users

        with session_scope() as dbsession:
            # version check
            version_record = db_anchore.get(session=dbsession)
            if not version_record:
                db_anchore.add(versions['service_version'], versions['db_version'], versions, session=dbsession)
                version_record = db_anchore.get(session=dbsession)

            if bootstrap_users:
                # system user
                try:
                    system_user_record = db_users.get('anchore-system', session=dbsession)
                    if not system_user_record:
                        rc = db_users.add('anchore-system', str(uuid.uuid4()), {'active': True}, session=dbsession)
                    else:
                        db_users.update(system_user_record['userId'], system_user_record['password'], {'active': True}, session=dbsession)

                except Exception as err:
                    raise Exception(
                        "Initialization failed: could not fetch/add anchore-system user from/to DB - exception: " + str(
                            err))

                try:
                    for userId in localconfig['credentials']['users']:
                        if not localconfig['credentials']['users'][userId]:
                            localconfig['credentials']['users'][userId] = {}

                        cuser = localconfig['credentials']['users'][userId]

                        password = cuser.pop('password', None)
                        email = cuser.pop('email', None)
                        if password and email:
                            # try:
                            #    from passlib.hash import pbkdf2_sha256
                            #    hashpw = pbkdf2_sha256.encrypt(password, rounds=200000, salt_size=16)
                            #    password = hashpw
                            # except:
                            #    pass
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
                    raise Exception(
                        "Initialization failed: could not add users from config into DB - exception: " + str(err))

        print ("Starting up version: " + json.dumps(versions))
        print ("\tDB version: " + json.dumps(version_record))

        try:
            rc = do_upgrade(version_record, versions)
            if rc:
                # if successful upgrade, set the DB values to the incode values
                with session_scope() as dbsession:
                    db_anchore.add(versions['service_version'], versions['db_version'], versions, session=dbsession)

        except Exception as err:
            raise Exception("Initialization failed: upgrade failed - exception: " + str(err))

    return (ret)


def do_upgrade(inplace, incode):
    global engine, upgrade_enabled, upgrade_functions

    if StrictVersion(inplace['db_version']) > StrictVersion(incode['db_version']):
        raise Exception("DB downgrade not supported")

    if inplace['db_version'] != incode['db_version']:
        print ("upgrading DB: from=" + str(inplace['db_version']) + " to=" + str(incode['db_version']))

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


def db_upgrade_001_002():
    global engine
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
    global engine
    from sqlalchemy import Column, BigInteger

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
    global engine
    from sqlalchemy import Column, String, BigInteger
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
    global engine
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
    global engine
    from sqlalchemy import Column, Integer, DateTime

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

@contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    global Session
    session = Session()

    # session.connection(execution_options={'isolation_level': 'SERIALIZABLE'})

    logger.spew("DB: opening session: " + str(session))
    logger.spew("DB: call stack: \n" + '\n'.join(traceback.format_stack()))
    try:
        yield session
        session.commit()
        logger.spew("DB: committing session: " + str(session))
    except:
        logger.spew("DB: rollbacking session: " + str(session))
        session.rollback()
        raise
    finally:
        logger.spew("DB: closing session: " + str(session))
        session.close()

def get_thread_scoped_session():
    """
    Return a thread scoped session for use. Caller must remove it when complete to ensure no leaks

    :return:
    """
    global ThreadLocalSession
    if not ThreadLocalSession:
        raise Exception(
            'Invoked get_session without first calling init_db to initialize the engine and session factory')

    # Will re-use a session if already in this thread-local context, otherwise will create a new one
    sess = ThreadLocalSession()
    return sess


def end_session():
    """
    Flushes thread-local sessions
    :return:
    """
    global ThreadLocalSession

    if ThreadLocalSession:
        ThreadLocalSession.remove()


def init_thread_session():
    """
    Configure a scoped session factory which is a thread-local session cache
    :return:
    """
    global ThreadLocalSession, engine
    if not ThreadLocalSession:
        ThreadLocalSession = scoped_session(sessionmaker(bind=engine))
