"""
This module is for testing the task subsystem of the policy engine.

This should be run against a postgresql db

"""
import uuid
import datetime
import time
from concurrent.futures.thread import ThreadPoolExecutor

from anchore_engine.db.entities.common import initialize, get_thread_scoped_session, session_scope, serializable_session
from anchore_engine.db.entities.policy_engine import DbLock, TaskState, acquire_db_lock, release_db_lock


def init_db():
    print('Initializing db')

    config = {
        'credentials': {
            'database': {
                'db_connect': 'postgresql+pg8000://postgres:postgres@localhost:54320/postgres',
                'db_connect_args' : {
                    'timeout': 120,
                    'ssl': False,
                    'db_pool_size': 5,
                    'db_pool_max_overflow': 10
                }
            }
        }
    }

    initialize(localconfig=config, versions={'service_version': "0.1.8dev", 'db_version':"0.0.4"}, bootstrap_db=True)


def run_test():
    print('Testing!')
    locks =[
        'testlock1',
        'testlock2'
    ]
    for l in locks:
        print('Initializing lock')
        result = DbLock.init_lock(l)
        print(('Did create new for lock {}: {}'.format(l, result)))

    iter_count = 10
    cycle(locks[0])
    native_test()

    # pool = ThreadPoolExecutor(max_workers=2)
    #
    # while iter_count > 0:
    #     for l in locks:
    #         pool.submit(cycle, l)
    #         pool.submit(cycle, l)
    #     iter_count -= 1


def native_test():
    print('Testing pg locks')
    acquire_db_lock(10)
    #time.sleep(60)
    #release_db_lock(10)


def cycle(lock_id):
    """
    Runs a single get-wait-release cycle
    :return:
    """

    my_id = uuid.uuid4().hex
    my_other_id = uuid.uuid4().hex

    print(('{} - Created id: {}'.format(time.time(), my_id)))

    lock = DbLock.acquire(my_id, lock_id=lock_id)

    if lock:
        if lock['held_by'] == my_id:
            print(('{} - {} Got lock {}'.format(time.time(), my_id, lock['lock_id'])))
        else:
            print(('{} - ERROR! Returned a lock object held by someone else: {}. Expected: {}'.format(time.time(), lock['held_by'], my_id)))
    else:
        print('Should have gotten the lock')
        return

    r = DbLock.acquire(my_other_id, lock_id=lock_id)
    if r is not None:
        print('Unexpectedly got a lock')
    else:
        print('Got none result as expected on failed lock acq.')

    print('Releasing, for other users')
    DbLock.release(lock, my_other_id)

    print('Releasing')
    DbLock.release(lock['lock_id'], my_id)



if __name__ == '__main__':
    init_db()
    run_test()




