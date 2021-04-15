from anchore_engine.db import db_locks
from contextlib import contextmanager
from threading import RLock, Lock, Condition

_lease_manager = None
mgr_lock = RLock()


def manager():
    """
    Return the configured lock manager instance

    :return:
    """
    global _lease_manager

    with mgr_lock as l:
        if _lease_manager is None:
            _lease_manager = DbLeaseManager()

    return _lease_manager


class DbLeaseManager(object):
    """
    Db backed lease manager
    """

    def list(self):
        return db_locks.getall()

    def get(self, lease_id):
        return db_locks.get(lease_id)

    def init_lease(self, lease_id):
        """
        Initialize a new named lease but do not acquire it. Idempotent.

        :param name:
        :return:
        """
        return db_locks.init_lease(lease_id)

    def acquire_lease(self, lease_id, client_id, ttl):
        """
        Acquire a ttl lease

        :param my_id:
        :param name:
        :param lease_timeout:
        :return:
        """
        return db_locks.acquire_lease(lease_id, client_id, ttl)

    def release_lease(self, lease_id, client_id, epoch):
        """
        Release the lease identified by the id, client, and epoch

        :param lease_id:
        :param client_id:
        :param epoch:
        :return:
        """
        return db_locks.release_lease(lease_id, client_id, epoch)

    def refresh(self, lease_id, client_id, epoch, ttl):
        """
        Update the ttl for the identified lease

        :param lease_id:
        :param client_id:
        :param ttl:
        :param epoch:
        :return:
        """
        return db_locks.refresh_lease(lease_id, client_id, epoch, ttl)


class ManyReadsOneWriteLock(object):
    """
    A lock implementation that allows multiple parallel reads, but blocks on a single
    thread performing a write.
    """

    def __init__(self):
        self.read_lock = Condition(Lock())
        self.read_counter = 0

    def _acquire_read_lock(self):
        """
        Acquire a read lock. Blocks if a thread has the write lock.
        """
        self.read_lock.acquire()
        try:
            self.read_counter += 1
        finally:
            self.read_lock.release()

    def _release_read_lock(self):
        """
        Release a read lock.
        """
        self.read_lock.acquire()
        try:
            self.read_counter -= 1
            if not self.read_counter:
                self.read_lock.notifyAll()
        finally:
            self.read_lock.release()

    @contextmanager
    def read_lock(self):
        try:
            yield self._acquire_read_lock
        finally:
            yield self._release_read_lock

    @contextmanager
    def _acquire_write_lock(self):
        """
        Acquire the write lock. Blocks until no threads have the read or write lock.
        """
        self.read_lock.acquire()
        while self.read_counter > 0:
            self.read_lock.wait()

    def _release_write_lock(self):
        """
        Release the write lock.
        """
        self.read_lock.release()

    @contextmanager
    def write_lock(self):
        try:
            yield self._acquire_write_lock
        finally:
            yield self._release_write_lock
