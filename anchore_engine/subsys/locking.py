from anchore_engine.db import db_locks
from threading import RLock

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
