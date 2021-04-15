import pytest
import _thread
import time

from anchore_engine.subsys.locking import ManyReadsOneWriteLock


def get_read_access(lock):
    lock._acquire_read_access()


def get_write_access(lock):
    lock._acquire_write_lock()


class TestManyReadOneWriteLock:

    def test_multiple_reads(self):
        # Init the lock
        lock = ManyReadsOneWriteLock()

        # Using the context manager, acquire read access
        with lock.read_access():
            assert lock.read_counter == 1

            # Simulate another thread getting read access
            lock._acquire_read_access()
            assert lock.read_counter == 2

        # Context manager automatically release read access, only the other caller now has read access
        assert lock.read_counter == 1

    def test_single_write(self):
        # Init the lock
        lock = ManyReadsOneWriteLock()

        # Using the context manager, acquire write access
        with lock.write_lock():
            # Reader count is 0
            assert lock.read_counter == 0

            # Try in a separate thread to get write access again
            _thread.start_new_thread(get_write_access, (lock, ))
            assert lock.read_counter == 0


    def test_write_blocks_read(self):
        lock = ManyReadsOneWriteLock()

        with lock.write_lock():
            assert lock.read_counter == 0

            _thread.start_new_thread(get_read_access, (lock,))
            assert lock.read_counter == 0

        time.sleep(1)
        assert lock.read_counter == 1


    def test_reads_block_write(self):
        lock = ManyReadsOneWriteLock()

        with lock.read_access():
            assert lock.read_counter == 1

            _thread.start_new_thread(get_write_access, (lock,))
            assert lock.read_counter == 1

        assert lock.read_counter == 0
