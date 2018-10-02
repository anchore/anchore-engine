from concurrent.futures.thread import ThreadPoolExecutor
import time
import uuid
import unittest

from anchore_engine.db import db_locks, initialize, session_scope, Lease
from anchore_engine.subsys import logger
from anchore_engine.subsys.logger import enable_bootstrap_logging

enable_bootstrap_logging()

conn_str = 'postgres+pg8000://postgres:postgres@localhost:54320/postgres'


def init():
    config = {
        'credentials':
            {'database':
                 {'db_connect': conn_str}
            }
    }
    initialize(localconfig=config)


class TestLocking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init()

    def test_serial_lock(self):
        id = uuid.uuid1().hex
        id2 = uuid.uuid1().hex
        lock_id = 'testlock'
        db_locks.init_lease(lock_id)

        r = db_locks.acquire_lease(lock_id, id)
        self.assertEqual(r['id'], lock_id)

        r2 = db_locks.acquire_lease(lock_id, id2)
        self.assertIsNone(r2, 'Should have failed to get the lock')

        self.assertIsNone(db_locks.release_lease(lock_id, id2, r2['epoch']))

        r3 = db_locks.acquire_lease(lock_id, id2)
        self.assertEqual(lock_id, r3['id'], 'Failed to get lock after free')

        self.assertIsNone(db_locks.release_lease(r['id'], r['held_by'], r['epoch']))
        self.assertIsNone(db_locks.release_lease(r3['id'], r['held_by'], r['epoch']))

    def test_expiration(self):
        lock_id = 'test_lock2'
        id = uuid.uuid4().hex
        id2 = uuid.uuid4().hex

        db_locks.init_lease(lock_id)

        l = db_locks.acquire_lease(lock_id, id, ttl=1)
        self.assertEqual(lock_id, l['id'])

        time.sleep(3)

        l2 = db_locks.acquire_lease(lock_id, id2, ttl=100)
        self.assertIsNotNone(l2)
        self.assertEqual(lock_id, l2['id'])

        self.assertIsNone(db_locks.release_lease(l2['id'], l2['held_by'], l2['epoch']))

    def _test_thread_lock(self, t):
        id = uuid.uuid4().hex
        lock_id = 'testlock'
        db_locks.init_lease(lock_id)
        count = 10

        r = None

        while count > 0:
            inner = 5

            while inner > 0:
                r = db_locks.acquire_lease(lock_id, id, ttl=t - 1)
                if not r:
                    time.sleep(t)
                    inner -= 1
                else:
                    break

            logger.info('{} Lock: {}'.format(id, r))
            logger.info('Sleeping for {}'.format(t))
            time.sleep(t)

            if r:
                db_locks.release_lease(r['id'], r['held_by'], r['epoch'])
                logger.info('{} Lock: {}'.format(id, r))

            count -= 1

        return 'Complete'

    def test_contextmgr(self):
        lockid = 'testlock'
        lockid2= 'test_lock_2'
        db_locks.init_lease(lockid)
        db_locks.init_lease(lockid2)
        with db_locks.least_with_ttl(lockid, 'myid123', ttl=10) as lt:
            print(lt)
            with session_scope() as db:
                print(('{}'.format('\n'.join([str(x) for x in db.query(Lease).all()]))))

        print(lt)

    def test_threads(self):
        th = []
        t = ThreadPoolExecutor(max_workers=3)
        th.append(t.submit(self._test_thread_lock, 2))
        th.append(t.submit(self._test_thread_lock, 5))
        th.append(t.submit(self._test_thread_lock, 1))

        for thread in th:
            # Wait for completion
            r = thread.result()
            print(('Thread result {}'.format(r)))


if __name__ == '__main__':
    unittest.main()