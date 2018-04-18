"""
Module for using db-based leases. These are implemented in db-agnostic ways so should be portable (e.g. not using postgresql advisory leases).

The general model for a DbLock that a lease is an entity in the db with an owner and a timeout that is updated with CAS operations.

These are *not* high performance leases and should not be used for anything that is either high frequency or requires very hard exclusion requirements since
this model uses lease timeouts to ensure that leases are released eventually in cases of process crashes or lost network connectivity.

These leases are re-entrant and not incrementing, so a single release() will release the lease regardless of number of acquire() calls by the owner.
"""

import time
from contextlib import contextmanager
from anchore_engine.db import Lease, session_scope
from anchore_engine.db.entities.exceptions import is_unique_violation, is_lock_acquisition_error
from anchore_engine.subsys import logger

DEFAULT_ACQUIRE_TIMEOUT_SECONDS = 3
DEFAULT_LOCK_DURATION_SECONDS = 10
REFRESH_RETRIES = 3

# Global application lock namespaces to isolate lock ids
# First layer of keys defined namespaces (the 'namespace' element is the id used in the db
# The 2nd layer of keys are named lock ids within each namespace.
application_lock_ids = {
    'upgrade': {
        'namespace': 1,
        'ids': {}
    },
    'archive_migration': {
        'namespace': 2,
        'ids': {
            'default': 1
        }
    }
}


def init_lease(lease_id):
    """
    Initilize a lease in the system idempotently. Does not acquire the lease, only ensures it exists.

    :param lease_id: string id (name) for the lease
    :return: True if initialized
    """
    logger.debug('Initializing lease {}'.format(lease_id))
    try:
        with session_scope() as db:
            f = Lease()
            f.id = lease_id
            f.held_by = None
            f.expires_at = None
            f.epoch = 0
            db.add(f)
            return True
    except Exception as e:
        if not is_unique_violation(e):
            logger.exception('Unexpected exception initializing lease in db: {}'.format(lease_id))
            raise e
        else:
            # Idempotent, and lease already exists
            return True


def getall():
    """
    Return a list of the states of all leases in the system
    :return: list of dicts
    """
    with session_scope() as db:
        return [x.to_json() for x in db.query(Lease).all()]


def get(lease_id):
    """
    Return the current state of the lease without changing it

    :param lease_id: str
    :return: list of dicts
    """
    with session_scope() as db:
        obj = db.query(Lease).get((lease_id))
        if obj:
            return obj.to_json()
        else:
            return None


def flush_lease(lease_id):
    """
    Delete the lease record. Warning: this is intended only for maintenance or shutdown operations to ensure epochs are reset etc and only when
    the system is halting. Calling this during execution will void the purpose of the epoch counters and could lead to incorrect lease behavior.

    :param lease_id:
    :return:
    """
    with session_scope() as db:
        lease = db.query(Lease).with_for_update(of=Lease).get((lease_id))
        if lease:
            db.delete(lease)
        return True


def acquire_lease(lease_id, client_id, ttl=DEFAULT_LOCK_DURATION_SECONDS, timeout=DEFAULT_ACQUIRE_TIMEOUT_SECONDS):
    """
    Try to acquire the lease. If fails, return None, else return lease object. The timeout is crudely implemented with backoffs and retries so the timeout is not precise

    :param client_id: the id to use to set the lease to the caller's identity
    :param lease_id: the lease name to aqcuire
    :param timeout: int (seconds) to keep retrying and waiting before giving up.
    :return: expiration time of the acquired lease or None if not acquired
    """

    logger.debug('Attempting to acquire lease {} for {}'.format(lease_id, client_id))

    t = 0
    while t < timeout:
        try:
            with session_scope() as db:
                ent = db.query(Lease).with_for_update(nowait=False, of=Lease).get((lease_id))
                if not ent:
                    raise KeyError(lease_id)

                if ent.do_acquire(client_id, duration_sec=ttl):
                    return ent.to_json()
        except Exception as e:
            if not is_lock_acquisition_error(e):
                logger.exception('Unexpected exception during lease acquire. Will retry')

        logger.debug('Retrying acquire of lease {} for {}'.format(lease_id, client_id))
        t += 1
        time.sleep(1)
    else:
        # Exceeded retry count, so failed to get lease
        logger.info('Failed to get lease {} for {} after {} retries'.format(lease_id, client_id, t))
        return None


def release_lease(lease_id, client_id, epoch):
    """
    Release the lease if i'm the owner, else raise exception that this caller (my_id) is not the owner.
        
    :param lease_id
    :param client_id
    :param epoch
    :return: None if released cleanly, else return the owner_id if my_id is not the lease holder
    """

    if not lease_id:
        raise ValueError(lease_id)
    if not client_id:
        raise ValueError(lease_id)
    if not epoch:
        raise ValueError(lease_id)

    logger.debug('Releasing lease {}'.format(lease_id))

    with session_scope() as db:
        lease = db.query(Lease).with_for_update(of=Lease, nowait=False).get((lease_id))
        if not lease:
            raise KeyError(lease_id)
        elif lease.held_by != client_id or lease.epoch > epoch:
            logger.warn('Lost the lease {}. Cannot update'.format(lease_id))
        else:
            lease.release_holder()

    return None


def refresh_lease(lease_id, client_id, epoch, ttl):
    """
    Update the timeout on the lease if my_id is the lease owner, else fail.

    :param lease_id:
    :param client_id:
    :param ttl: number of seconds in the future to set the expiration to, can lengthen or shorten expiration depending on current value of lease.
    :param epoch:
    :return: new expiration datetime
    """
    if not lease_id:
        raise ValueError(lease_id)
    if not client_id:
        raise ValueError(client_id)
    if not epoch:
        raise ValueError(epoch)
    if not ttl:
        raise ValueError(ttl)

    retries = REFRESH_RETRIES

    logger.debug('Refreshing lease {}'.format(lease_id))

    while retries > 0:
        try:
            with session_scope() as db:
                lease = db.query(Lease).with_for_update(of=Lease, nowait=False).get((lease_id))
                if not lease:
                    raise KeyError(lease_id)
                if lease.held_by != client_id:
                    raise Exception('Lock no longer held by this id')
                else:
                    lease.set_holder(lease.held_by, duration_sec=ttl)
                    return lease.to_json()
        except KeyError:
            raise
        except Exception as e:
            if not is_lock_acquisition_error(e):
                logger.exception('Failed updating lease duration for {} due to exception'.format(lease_id))

        retries -= 1
    else:
        logger.error('Failed updating lease duration {} after all retries'.format(lease_id))
        return None


@contextmanager
def least_with_ttl(lease_id, client_id, ttl):
    """
    Convenience context manager for executing code wrapped in a lease with the given duration.
    Note that the duration is not enforced and only defines the expiration of the lease when acquired.

    :param client_id:
    :param lease_id:
    :param ttl:
    :return:
    """
    timeout = 2
    l = acquire_lease(client_id=client_id, lease_id=lease_id, timeout=timeout, ttl=ttl)
    if l:
        try:
            yield l
        finally:
            release_lease(l['id'], l['held_by'], l['epoch'])
    else:
        return


@contextmanager
def db_application_lock(engine, lock_id):
    """
    Provide a context with an acquired application lock from postgresql.
    This is postgresql specific code as it uses native features of postgres.

    :param lock_id:
    :return: context object
    """
    got_lock_id = None
    try:
        logger.debug('Acquiring pg advisory lock {}'.format(lock_id))
        if type(lock_id) == tuple:
            result = engine.execute('select pg_advisory_lock({}, {});'.format(lock_id[0], lock_id[1])).first()
        else:
            result = engine.execute('select pg_advisory_lock({});'.format(lock_id)).first()

        if result is not None:
            got_lock_id = lock_id
            yield got_lock_id
        else:
            got_lock_id = None
            raise Exception('No lock available')
    finally:
        if got_lock_id:
            logger.debug('Releasing pg advisory lock {}'.format(got_lock_id))
            if type(lock_id) == tuple:
                result = engine.execute('select pg_advisory_unlock({}, {});'.format(lock_id[0], lock_id[1]))
            else:
                result = engine.execute('select pg_advisory_unlock({});'.format(lock_id))




