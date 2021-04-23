"""
Tests the feed data fetcher
"""
import datetime
import json
import os
import tempfile
from os import path
from typing import Callable

import pytest

from anchore_engine.common.schemas import (
    DownloadOperationResult,
    GroupDownloadResult,
    LocalFeedDataRepoMetadata,
)
from anchore_engine.services.policy_engine.engine.feeds.download import (
    FeedDataFileJsonIterator,
    FeedDownloader,
    FileData,
    FileListIterator,
    FileListJsonIterator,
    LocalFeedDataRepo,
)
from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_bytes, timer
from tests.utils import init_test_logging

init_test_logging(level="debug")

ANCHOREIO_URI = "https://ancho.re/v1/service/feeds"

SIMPLE_DATA = {
    "next_token": "sometokenvalue",
    "data": [
        {"vulnerability": "vuln1"},
        {"vulnerability": "vuln2"},
        {"vulnerability": "vuln3"},
    ],
    "since": "2020-01-01T00:00:00Z",
}

SEQUENCE_DATA = [
    {
        "next_token": "sometokenvalue",
        "data": [
            {"vulnerability": "vuln1"},
            {"vulnerability": "vuln2"},
            {"vulnerability": "vuln3"},
        ],
        "since": "2020-01-01T00:00:00Z",
    },
    {
        "next_token": "sometokenvalue2",
        "data": [
            {"vulnerability": "vuln4"},
            {"vulnerability": "vuln5"},
            {"vulnerability": "vuln6"},
        ],
        "since": "2020-01-01T00:00:00Z",
    },
    {
        "next_token": "sometokenvalue3",
        "data": [
            {"vulnerability": "vuln7"},
            {"vulnerability": "vuln8"},
            {"vulnerability": "vuln9"},
        ],
        "since": "2020-01-01T00:00:00Z",
    },
]

CURRENT_DIR = path.dirname(path.abspath(__file__))


@pytest.fixture
def get_file(
    request,
) -> Callable[[str,], str]:
    module_filename_with_extension = path.basename(request.module.__file__)
    module_filename = path.splitext(module_filename_with_extension)[0]

    def _get_file(filename: str):
        file_path = path.join(CURRENT_DIR, module_filename, filename)
        return file_path

    return _get_file


@pytest.fixture
def feed_json_file():
    f = tempfile.NamedTemporaryFile("w+b")
    b = ensure_bytes(json.dumps(SIMPLE_DATA))
    f.write(b)
    f.seek(0)
    return f


@pytest.fixture
def feed_json_file_array():
    files = []
    for i in range(3):
        f = tempfile.NamedTemporaryFile("w+b", prefix="file-{}-".format(i))
        b = ensure_bytes(json.dumps(SEQUENCE_DATA[i]))
        f.write(b)
        f.seek(0)
        files.append(f)

    return files


class TestLocalFeedDataRepo:
    def test_file_iterator(self, feed_json_file):
        counter = 0
        with FeedDataFileJsonIterator(feed_json_file.name) as jsonitr:
            for record in jsonitr:
                logger.debug("Record {}".format(record))
                assert record == SIMPLE_DATA["data"][counter]
                counter += 1

        feed_json_file.close()
        assert counter == len(SIMPLE_DATA.get("data"))

    def test_fileset_iterator(self, feed_json_file_array):
        last_rec = 0
        itr = FileListJsonIterator([x.name for x in feed_json_file_array], 0)
        for record in itr:
            logger.debug("Record {}".format(record))
            idx = int(record["vulnerability"][-1])
            assert last_rec < idx
            last_rec = idx

        # Cleanup
        for f in feed_json_file_array:
            f.close()

    def test_local_feed_data_repo(self):
        tmpdir = tempfile.mkdtemp(prefix="anchoretest_repo-")
        r = LocalFeedDataRepo(metadata=LocalFeedDataRepoMetadata(data_write_dir=tmpdir))
        try:
            assert os.listdir(tmpdir) == []

            r.initialize()
            assert os.listdir(tmpdir) == ["metadata.json"]
            ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            r.metadata.download_result = DownloadOperationResult(
                started=ts, status=FeedDownloader.State.in_progress.value, results=[]
            )
            r.flush_metadata()
            r.metadata = None
            r.reload_metadata()
            assert r.metadata.download_result.started == ts
            assert (
                r.metadata.download_result.status
                == FeedDownloader.State.in_progress.value
            )

            r.write_data(
                "feed1",
                "group1",
                chunk_id=0,
                data=b'{"next_token": "something", "data": [{"somekey": "somevalue"}]}',
            )

            with timer("Read single record group", log_level="info"):
                found_count = 0
                for i in r.read("feed1", "group1", start_index=0):
                    logger.info("Got record {}".format(i))
                    found_count += 1

            logger.info("Repo metadata: {}".format(r.metadata))

            assert found_count > 0

        finally:
            logger.info("Done with repo test")
            r.teardown()

    def test_local_feed_data_repo_read_files(self, get_file):
        """
        Test writing chunks of binary data to LocalFeedDataRepo and reading using LocalFeedDataRepo.read_files()
        """
        tmpdir = tempfile.mkdtemp(prefix="anchoretest_repo-")
        r = LocalFeedDataRepo(metadata=LocalFeedDataRepoMetadata(data_write_dir=tmpdir))
        try:
            r.initialize()
            ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
            meta = GroupDownloadResult(
                feed="feed1",
                group="group1",
                total_records=0,
                status=FeedDownloader.State.in_progress.value,
                started=datetime.datetime.utcnow(),
                group_metadata={},
            )
            r.metadata.download_result = DownloadOperationResult(
                started=ts, status=FeedDownloader.State.in_progress.value, results=[meta]
            )
            expected_output = []
            for chunk_number in range(2):
                with open(get_file(f"{chunk_number}.data"), "rb") as f:
                    binary_content = f.read()
                    expected_output.append(binary_content)
                group_metadata = {str(chunk_number): {"test_value": str(chunk_number)}}
                r.write_data(
                    "feed1",
                    "group1",
                    chunk_id=chunk_number,
                    data=binary_content,
                )
                meta.total_records += 1
                meta.group_metadata.update(group_metadata)
            meta.status = FeedDownloader.State.complete.value
            meta.ended = datetime.datetime.utcnow()
            r.flush_metadata()
            r.metadata = None
            r.reload_metadata()
            assert r.metadata.download_result.results[0].total_records == 2
            assert all([x in r.metadata.download_result.results[0].group_metadata for x in ["0", "1"]])
            found_count = 0
            for idx, file_data in enumerate(r.read_files("feed1", "group1")):
                found_count += 1
                assert isinstance(file_data, FileData)
                assert file_data.data == expected_output[idx]
                assert str(idx) in meta.group_metadata
                assert file_data.metadata["test_value"] == str(idx)
            assert found_count == 2
        finally:
            r.teardown()

    def test_file_list_iterator(self, get_file):
        file_paths = []
        group_metadata = {}
        for idx in range(2):
            file_paths.append(get_file(f"{idx}.data"))
            group_metadata.update({f"{idx}.data": {"test_value": str(idx)}})
        logger.error(json.dumps(file_paths))
        iterator = FileListIterator(file_paths, group_metadata)
        for idx, file_data in enumerate(iterator):
            assert isinstance(file_data, FileData)
            with open(file_paths[idx], "rb") as f:
                expected_data = f.read()
            assert expected_data == file_data.data
            assert group_metadata[f"{idx}.data"] == file_data.metadata
