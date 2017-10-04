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
def initialize(versions=None, bootstrap_db=False, specific_tables=None, bootstrap_users=False):
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

            if bootstrap_users:
                # system user
                try:
                    system_user_record = db_users.get('anchore-system', session=dbsession)
                    if not system_user_record:
                        rc = db_users.add('anchore-system', str(uuid.uuid4()), {'active': True}, session=dbsession)
                        #system_user_record = db_users.get('anchore-system', session=dbsession)
                    else:
                        db_users.update(system_user_record['userId'], system_user_record['password'], {'active': True}, session=dbsession)
                        #system_user_record = db_users.get('anchore-system', session=dbsession)

                    #localconfig['anchore-system-password'] = system_user_record['password']

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
                    print ("upgrading from 0.0.1 to 0.0.2")
                    try:
                        rc = db_upgrade_001_002()
                    except Exception as err:
                        raise err

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

    if False:
        try:
            table_name = 'catalog_image'
            column = Column('image_content_metadata', String, primary_key=False)
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute('ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s' % (table_name, cn, ct))

            with session_scope() as dbsession:
                image_records = db_catalog_image.get_all(session=dbsession)
                for image_record in image_records:
                    try:
                        if not image_record['image_content_metadata']:
                            image_record['image_content_metadata'] = json.dumps({})
                            db_catalog_image.update_record(image_record, session=dbsession)
                    except Exception as err:
                        pass

        except Exception as err:
            raise Exception("failed to perform DB catalog_image table upgrade - exception: " + str(err))

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
