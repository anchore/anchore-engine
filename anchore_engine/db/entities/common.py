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

import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger

# Separate logger for use during bootstrap when logging may not be fully configured
from twisted.python import log

Session = None  # Standard session maker
ThreadLocalSession = None  # Separate thread-local session maker
engine = None
Base = declarative_base()


def anchore_now():
    """
    Simple epoch time fetcher

    :return: integer unix epoch time
    """
    return (int(time.time()))


# some DB management funcs
def initialize(versions=None, bootstrap_db=False, specific_tables=None):
    """
    Initialize the db for use. Optionally bootstrap it and optionally only for specific entities.

    :param versions:
    :param bootstrap_db:
    :param specific_entities: a list of entity classes to initialize if a subset is desired. Expects a list of classes.
    :return:
    """
    global engine, Session

    if versions is None:
        versions = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()

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

    db_connect_retry_max = 3
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
                time.sleep(10)

    if bootstrap_db:
        from anchore_engine.db import db_anchore, db_users

        with session_scope() as dbsession:
            # version check
            version_record = db_anchore.get(session=dbsession)
            if not version_record:
                db_anchore.add(versions['service_version'], versions['db_version'], versions, session=dbsession)
                version_record = db_anchore.get(session=dbsession)

            # system user
            try:
                system_user_record = db_users.get('anchore-system', session=dbsession)
                if not system_user_record:
                    rc = db_users.add('anchore-system', str(uuid.uuid4()), {}, session=dbsession)
                    system_user_record = db_users.get('anchore-system', session=dbsession)
                localconfig['anchore-system-password'] = system_user_record['password']

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
                        db_users.add(userId, password, {'email': email}, session=dbsession)
                    else:
                        raise Exception("user defined but has empty password/email: " + str(userId))

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
    global engine

    if StrictVersion(inplace['db_version']) > StrictVersion(incode['db_version']):
        raise Exception("DB downgrade not supported")

    if inplace['db_version'] != incode['db_version']:
        print ("upgrading DB: from=" + str(inplace['db_version']) + " to=" + str(incode['db_version']))

        if True:
            # set up possible upgrade chain
            db_upgrade_map = [
                ('0.0.1', '0.0.2')
            ]

            db_current = inplace['db_version']
            db_target = incode['db_version']
            for db_from, db_to in db_upgrade_map:

                # finish if we've reached the target version
                if StrictVersion(db_current) >= StrictVersion(db_target):
                    # done
                    break

                # this is just example code for now - have a clause for each possible from->to in the upgrade chain
                if db_current == '0.0.1' and db_to == '0.0.2':
                    print ("upgrade from 0.0.1 to 0.0.2")
                    try:
                        rc = db_upgrade_001_002()
                    except Exception as err:
                        raise err

                elif db_current == '0.0.2' and db_to == '0.0.3':
                    print ("upgrade from 0.0.2 to 0.0.3")
                    try:
                        table_name = 'subscriptions'
                        column = Column('foobar', String, primary_key=False)
                        cn = column.compile(dialect=engine.dialect)
                        ct = column.type.compile(engine.dialect)
                        engine.execute('ALTER TABLE %s DROP COLUMN IF EXISTS %s' % (table_name, cn))
                    except Exception as err:
                        raise err

                db_current = db_to

    if inplace['service_version'] != incode['service_version']:
        print ("upgrading service: from=" + str(inplace['service_version']) + " to=" + str(incode['service_version']))

    ret = True
    return (ret)


def db_upgrade_001_002():
    global engine

    table_name = 'catalog_image_docker'
    column = Column('created_at', Integer, primary_key=False)
    cn = column.compile(dialect=engine.dialect)
    ct = column.type.compile(engine.dialect)
    engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))

    import db.db_users, db.db_catalog_image_docker
    with session_scope() as dbsession:
        all_users = db.db_users.get_all(session=dbsession)
        for user in all_users:
            userId = user['userId']
            all_records = db.db_catalog_image_docker.get_all(userId, session=dbsession)
            for record in all_records:
                if not record['created_at']:
                    record['created_at'] = time.time()
                    db.db_catalog_image_docker.update_record(record, session=dbsession)

    return (True)


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
    global Session

    if Session:
        ThreadLocalSession.remove()


def disconnect():
    global ThreadLocalSession, Session, engine

    if ThreadLocalSession:
        ThreadLocalSession.close_all()
        ThreadLocalSession = None
    if Session:
        Session.close_all()
        Session = None

    if engine:
        engine.dispose()
        engine = None

def init_thread_session():
    """
    Configure a scoped session factory which is a thread-local session cache
    :return:
    """
    global ThreadLocalSession, engine
    if not ThreadLocalSession:
        ThreadLocalSession = scoped_session(sessionmaker(bind=engine))
