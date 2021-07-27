import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, Mock, patch

import pytest

from anchore_engine.db import GrypeDBFeedMetadata
from anchore_engine.db.db_grype_db_feed_metadata import NoActiveGrypeDB
from anchore_engine.services.policy_engine.engine.feeds.grypedb_sync import (
    GrypeDBSyncLock,
    GrypeDBSyncLockAquisitionTimeout,
    GrypeDBSyncManager,
    NoActiveDBSyncError,
)


class TestGrypeDBSyncTask:
    @pytest.fixture
    def mock_query_active_dbs_with_data(self, monkeypatch):
        """
        Creates factory that will mock _query_active_dbs return with params passed
        """

        def _mock_query(mocked_output):
            def _mocked_call(session):
                return mocked_output

            monkeypatch.setattr(
                "anchore_engine.services.policy_engine.engine.feeds.grypedb_sync.get_most_recent_active_grypedb",
                _mocked_call,
            )

        return _mock_query

    @pytest.fixture
    def mock_get_local_grypedb_checksum(self, monkeypatch):
        """
        Creates factory that will mock _query_active_dbs return with params passed
        """

        def _mock_query(mocked_output):
            monkeypatch.setattr(
                GrypeDBSyncManager,
                "_get_local_grypedb_checksum",
                Mock(return_value=mocked_output),
            )

        return _mock_query

    @pytest.fixture
    def mock_calls_for_sync(
        self, mock_query_active_dbs_with_data, mock_get_local_grypedb_checksum
    ):
        """
        Provides ability to mock all class methods necessary to run a sync as a unit test
        """

        def _mock(mock_active_db=[], mock_local_checksum=""):
            mock_query_active_dbs_with_data(mock_active_db)
            mock_get_local_grypedb_checksum(mock_local_checksum)

        return _mock

    @pytest.fixture
    def setup_for_thread_testing(self, mock_calls_for_sync, monkeypatch):
        """
        2 tests that run tests for threads and locking use the same mock data captured in this fixture
        """
        old_checksum = (
            "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        )
        new_checksum = (
            "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        )

        # mock initial state so execution occurs
        mock_calls_for_sync(GrypeDBFeedMetadata(archive_checksum=old_checksum), "")

        # Mock the update_grypedb method for task to sleep and update mocks for active and local grype dbs
        def _mock_update_grypedb_for_thread1(
            active_grypedb=None, grypedb_file_path=None
        ):
            # sleep to ensure lock is taken
            time.sleep(10)

            # mock the returns to mimic persistent change of active grypedb local and global
            # This in effect mocks the actual execution for the first thread
            mock_calls_for_sync(
                GrypeDBFeedMetadata(archive_checksum=new_checksum), new_checksum
            )

        monkeypatch.setattr(
            GrypeDBSyncManager, "_update_grypedb", _mock_update_grypedb_for_thread1
        )

    def test_no_active_grypedb(self, monkeypatch):
        def _mocked_call(session):
            raise NoActiveGrypeDB

        monkeypatch.setattr(
            "anchore_engine.services.policy_engine.engine.feeds.grypedb_sync.get_most_recent_active_grypedb",
            _mocked_call,
        )

        with pytest.raises(NoActiveDBSyncError):
            GrypeDBSyncManager.run_grypedb_sync(Mock())

    def test_matching_checksums(self, mock_calls_for_sync):
        checksum = "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        mock_calls_for_sync(
            mock_active_db=GrypeDBFeedMetadata(archive_checksum=checksum),
            mock_local_checksum=checksum,
        )

        sync_ran = GrypeDBSyncManager.run_grypedb_sync(Mock())

        assert sync_ran is False

    def test_mismatch_checksum(self, mock_calls_for_sync, monkeypatch):
        global_checksum = (
            "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c"
        )
        local_checksum = (
            "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        )

        mock_calls_for_sync(
            mock_active_db=GrypeDBFeedMetadata(archive_checksum=global_checksum),
            mock_local_checksum=local_checksum,
        )

        # mock execution of update
        monkeypatch.setattr(
            GrypeDBSyncManager, "_update_grypedb", Mock(return_value=True)
        )

        # pass a file path to bypass connection to catalog to retrieve tar from object storage
        sync_ran = GrypeDBSyncManager.run_grypedb_sync(
            Mock(), grypedb_file_path="test/bypass/catalog.txt"
        )

        assert sync_ran is True

    def test_uninitialized_grype_wrapper(self):
        assert GrypeDBSyncManager._get_local_grypedb_checksum() is None

    def test_class_lock_called(self, mock_calls_for_sync, monkeypatch):
        """
        Verfies that the lock enter and exit methods are called to ensure that the lock is being used correctly
        Verifies on matching checksum in order to assert the lock is called even when the task is not executed
        """
        checksum = "366ab0a94f4ed9c22f5cc93e4d8f6724163a357ae5190740c1b5f251fd706cc4"
        mock_lock = MagicMock()
        monkeypatch.setattr(GrypeDBSyncLock, "_lock", mock_lock)
        mock_calls_for_sync(
            mock_active_db=GrypeDBFeedMetadata(archive_checksum=checksum),
            mock_local_checksum="",
        )

        monkeypatch.setattr(
            GrypeDBSyncManager, "_update_grypedb", Mock(return_value=True)
        )

        sync_ran = GrypeDBSyncManager.run_grypedb_sync(
            Mock(), grypedb_file_path="test/bypass/catalog.txt"
        )

        assert sync_ran is True
        assert mock_lock.acquire.called is True
        assert mock_lock.release.called is True

    def test_lock_across_threads(self, setup_for_thread_testing):
        """
        Verifies the output of the tasks when designed to ensure that one thread hits the lock before the other finishes

        Runs 2 tasks: creates thread that runs sync task and then another task is run synchronously (synchronous_task)
        Mocks the update_grypedb function to wait 5 seconds to ensure race condition with thread1 and synchronous_task
        The mock also updates active and local grype dbs to mimic real behavior
        Run thread1 and once the lock is taken, it runs synchronous_task, which is identical to thread1
        If lock correctly blocks synchronous_task from evaluating, only thread1 should run the update_grypedb method
        """

        with ThreadPoolExecutor() as executor:
            # run thread1
            thread1 = executor.submit(
                GrypeDBSyncManager.run_grypedb_sync, "test/bypass/catalog.txt"
            )

            # Wait until thread1 has taken the lock and then run thread2 with timeout of ~5 seconds
            synchronous_task = False
            lock_acquired = False
            for attempt in range(10):
                if GrypeDBSyncLock._lock.locked():
                    lock_acquired = True
                    synchronous_task = GrypeDBSyncManager.run_grypedb_sync(
                        Mock(), grypedb_file_path="test/bypass/catalog.txt"
                    )
                    break
                else:
                    time.sleep(1)

            assert thread1.result() is True
            assert lock_acquired is True
            assert synchronous_task is False

    @patch(
        "anchore_engine.services.policy_engine.engine.feeds.grypedb_sync.LOCK_AQUISITION_TIMEOUT",
        1,
    )
    def test_lock_timeout(self, setup_for_thread_testing):
        """
        Verifies that error is raised when the lock timeout is met by a thread
        Ensures this happening by creating a thread that runs longer than timeout
        Runs task while lock is taken and assert that error is raised
        Patches timeout to 1 second
        """
        with ThreadPoolExecutor() as executor:
            # run thread1
            thread1 = executor.submit(
                GrypeDBSyncManager.run_grypedb_sync, Mock(), "test/bypass/catalog.txt"
            )

            # Wait until thread1 has taken the lock and then run thread2 with timeout of ~5 seconds
            lock_acquired = False
            for attempt in range(5):
                if GrypeDBSyncLock._lock.locked():
                    lock_acquired = True
                    with pytest.raises(GrypeDBSyncLockAquisitionTimeout):
                        GrypeDBSyncManager.run_grypedb_sync(
                            Mock(), grypedb_file_path="test/bypass/catalog.txt"
                        )
                    break
                else:
                    time.sleep(1)

            assert thread1.result() is True
            assert lock_acquired is True
