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
        self.lock = Condition(Lock())
        self.read_counter = 0

    def _acquire_read_access(self):
        """
        Acquire read access. Blocks if a thread has write access.
        Avoid calling this directly outside of tests, use read_access() instead.
        """
        self.lock.acquire()
        try:
            self.read_counter += 1
        finally:
            self.lock.release()

    def _release_read_access(self):
        """
        Release the calling thread's read access.
        If no other threads have read access, notify any waiting for write access.
        Avoid calling this directly outside of tests, use read_access() instead.
        """
        self.lock.acquire()
        try:
            self.read_counter -= 1
            if not self.read_counter:
                self.lock.notifyAll()
        finally:
            self.lock.release()

    @contextmanager
    def read_access(self):
        """
        Context manager for read access to a resource. Allows (unlimited) multiple threads
        to have read access to the resource.
        """
        try:
            yield self._acquire_read_access()
        finally:
            self._release_read_access()

    @contextmanager
    def _acquire_write_lock(self):
        """
        Acquire write access. Blocks until no threads have read or write access.
        Avoid calling this directly outside of tests, use read_access() instead.
        """
        self.lock.acquire()
        while self.read_counter > 0:
            self.lock.wait()

    def _release_write_lock(self):
        """
        Release the calling thread's write access.
        Avoid calling this directly outside of tests, use read_access() instead.
        """
        self.lock.release()

    @contextmanager
    def write_lock(self):
        """
        Context manager for write access to a resource. Limits access to the resource to a single
        thread at a time.
        """
        try:
            yield self._acquire_write_lock()
        finally:
            self._release_write_lock()
