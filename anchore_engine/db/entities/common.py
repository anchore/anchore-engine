"""
Common functions and variables for all entity types including some bootstrap and init functions
"""

import json
import uuid
import time
import traceback
from contextlib import contextmanager

import sqlalchemy
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
def get_engine():
    global engine
    return(engine)

def test_connection():
    global engine

    test_connection = None
    try:
        test_connection = engine.connect()
    except Exception as err:
        raise Exception("test connection failed - exception: " + str(err))
    finally:
        if test_connection:
            test_connection.close()
    return(True)

def do_connect(db_params):
    global engine, Session, SerializableSession

    db_connect = db_params.get('db_connect', None)
    db_connect_args = db_params.get('db_connect_args', None)
    db_pool_size = db_params.get('db_pool_size', None)
    db_pool_max_overflow = db_params.get('db_pool_max_overflow', None)

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

    return(True)

def do_disconnect():
    global engine
    if engine:
        engine.dispose()

def get_params(localconfig):
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

    ret = {
        'db_connect': db_connect,
        'db_connect_args': db_connect_args,
        'db_pool_size': db_pool_size,
        'db_pool_max_overflow': db_pool_max_overflow
    }
    return(ret)

def do_create(specific_tables):
    global engine, Base

    try:
        if specific_tables:
            logger.info('Initializing only a subset of tables as requested: {}'.format(specific_tables))
            Base.metadata.create_all(engine, tables=specific_tables)
        else:
            Base.metadata.create_all(engine)
    except Exception as err:
        raise Exception("could not create/re-create DB tables - exception: " + str(err))


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

    ret = True

    # get params from configuration
    db_params = get_params(localconfig)

    # enter loop to try connecting to the DB - upon connect, create the ORM tables if they dont exist
    db_connect_retry_max = 60
    for count in range(0, db_connect_retry_max):
        try:
            # connect
            rc = do_connect(db_params)

            # test the connection
            rc = test_connection()

            # create
            rc = do_create(specific_tables)

            break
        except Exception as err:
            if count > db_connect_retry_max:
                raise Exception("ERROR: could not establish connection to DB after retries - last exception: " + str(err))
            else:
                log.err("WARN: could not connect to/initialize db, retrying in 5 seconds - exception: " + str(err))
                time.sleep(5)

    # these imports need to be here, after the connect/creates have happened
    from anchore_engine.db import db_anchore, db_users
    
    with session_scope() as dbsession:
        # version check
        version_record = db_anchore.get(session=dbsession)

        if bootstrap_db:
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

    # finally, check to make sure that the running code DB version is == the running DB version
    try:
        print ("Starting up version: " + json.dumps(versions))
        print ("\tDB version: " + json.dumps(version_record))

        # version checks
        code_db_version = versions.get('db_version', None)
        running_db_version = version_record.get('db_version', None)

        if not code_db_version or not running_db_version:
            raise Exception("cannot get either the running DB version or support code DB version: (running/code) (" + str([running_db_version, code_db_version]) + ")")
        elif code_db_version != running_db_version:
            raise Exception("DB version mismatch - code code_db_version="+str(code_db_version)+" running_db_version="+str(running_db_version)+" - will need to sync the DB version with this version of anchore-engine before the service will start.")
        else:
            logger.info("DB version checks passed")

    except Exception as err:
        raise err

    return (ret)

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


