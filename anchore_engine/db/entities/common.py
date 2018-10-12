"""
Common functions and variables for all entity types including some bootstrap and init functions
"""

import json
import uuid
import time
import traceback
from contextlib import contextmanager

import sqlalchemy
from sqlalchemy import types
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
        for a in list(inobj.keys()):
            if hasattr(self, a):
                setattr(self, a, inobj[a])

    def to_json(self):
        """
        Returns json-encoded string representation of the object's members. If datetime.datetime object is found, converts it to iso8601 format

        NOTE: this is a very simple implementation that assumes members are simple types. If an object has complex types as member, that
        class should override this function with an impl that serializes those types properly for json.

        :return: string
        """
        return dict((key, value if type(value) != datetime.datetime else value.isoformat()) for key, value in vars(self).items() if not key.startswith('_'))

    def to_dict(self):
        """
        Returns a dictionary version of the object. Basically the same as json(), but leaves types unchanged whereas json() does encoding to strings for
        things like datetime objects.

        :return:
        """

        return dict((key, value) for key, value in vars(self).items() if not key.startswith('_'))

    def to_detached(self):
        """
        To be called inside a transaction to create a new entity object with values that are the same as the current object but not part of a transaction and without any
        transaction/session dependencies so can be used outside of session.
        :return: instance(self.__class__)
        """

        obj = self.__class__()
        for name, attr in vars(self).items():
            if not name.startswith('_'):
                setattr(obj, name, attr)

        return obj


def anchore_now():
    """
    Simple epoch time fetcher

    :return: integer unix epoch time
    """
    return (int(time.time()))


def anchore_now_datetime():
    return datetime.datetime.utcnow()


def anchore_uuid():
    return uuid.uuid4().hex


def get_entity_tables(entity):
    global Base

    import inspect
            
    entity_names = [x[1].__tablename__ for x in [x for x in inspect.getmembers(entity) if inspect.isclass(x[1]) and issubclass(x[1], Base) and x[1] != Base]]
    ftables = [x for x in Base.metadata.sorted_tables if x.name in entity_names]

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
    db_echo = db_params.get('db_echo', False)

    if db_connect:
        try:
            if db_connect.startswith('sqlite://'):
                # Special case for testing with sqlite. Not for production use, unit tests only
                engine = sqlalchemy.create_engine(db_connect, echo=db_echo)
            else:
                logger.debug("database connection args {} db_echo={}".format(db_connect_args, db_echo))
                engine = sqlalchemy.create_engine(db_connect, connect_args=db_connect_args, echo=db_echo,
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
        db_pool_size = 30
        db_pool_max_overflow = 75
        db_echo = False

        if 'db_connect' in db_auth and db_auth['db_connect']:
            db_connect = db_auth['db_connect']
        if 'db_connect_args' in db_auth and db_auth['db_connect_args']:
            db_connect_args = db_auth['db_connect_args']
        if 'db_pool_size' in db_auth:
            db_pool_size = int(db_auth['db_pool_size'])
        if 'db_pool_max_overflow' in db_auth:
            db_pool_max_overflow = int(db_auth['db_pool_max_overflow'])
        if 'db_echo' in db_auth:
            db_echo = db_auth['db_echo'] in [True, 'True', 'true']
    except:
        raise Exception(
            "could not locate credentials->database entry from configuration: add 'database' section to 'credentials' section in configuration file")

    ret = {
        'db_connect': db_connect,
        'db_connect_args': db_connect_args,
        'db_pool_size': db_pool_size,
        'db_pool_max_overflow': db_pool_max_overflow,
        'db_echo': db_echo
    }
    return(ret)

def do_create(specific_tables=None, base=Base):
    engine = get_engine()
    try:
        if specific_tables:
            logger.info('Initializing only a subset of tables as requested: {}'.format(specific_tables))
            base.metadata.create_all(engine, tables=specific_tables)
        else:
            base.metadata.create_all(engine)
    except Exception as err:
        raise Exception("could not create/re-create DB tables - exception: " + str(err))


def initialize(localconfig=None, versions=None):
    """
    Initialize the db for use

    :param localconfig: the global configuration
    :param versions:
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

            break
        except Exception as err:
            if count > db_connect_retry_max:
                raise Exception("ERROR: could not establish connection to DB after retries - last exception: " + str(err))
            else:
                log.err("WARN: could not connect to/initialize db, retrying in 5 seconds - exception: " + str(err))
                time.sleep(5)

    return (ret)


def get_session():
    global Session
    return Session()

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


class StringJSON(types.TypeDecorator):
    """
    A generic json text type for serialization and deserialization of json to text columns.
    Note: will not detect modification of the content of the dict as an update. To update must change and re-assign the
    value to the column rather than in-place updates.

    """
    impl = types.TEXT

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
            return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value
