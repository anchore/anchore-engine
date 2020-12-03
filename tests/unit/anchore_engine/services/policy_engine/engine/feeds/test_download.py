"""
Tests the feed data fetcher
"""

import datetime
import pytest
import tempfile
import json
import os

from tests.utils import init_test_logging
import logging as logger
from anchore_engine.services.policy_engine.engine.feeds.download import (
    FeedDataFileJsonIterator,
    FileListJsonIterator,
    LocalFeedDataRepo,
    FeedDownloader,
)
from anchore_engine.common.schemas import (
    DownloadOperationResult,
    LocalFeedDataRepoMetadata,
)
from anchore_engine.utils import ensure_bytes, timer

init_test_logging(level="debug")

ANCHOREIO_URI = "https://ancho.re/v1/service/feeds"

simple_data = {
    "next_token": "sometokenvalue",
    "data": [
        {"vulnerability": "vuln1"},
        {"vulnerability": "vuln2"},
        {"vulnerability": "vuln3"},
    ],
    "since": "2020-01-01T00:00:00Z",
}

sequence_data = [
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


@pytest.fixture
def feed_json_file():
    f = tempfile.NamedTemporaryFile("w+b")
    b = ensure_bytes(json.dumps(simple_data))
    f.write(b)
    f.seek(0)
    return f


@pytest.fixture
def feed_json_file_array():
    files = []
    for i in range(3):
        f = tempfile.NamedTemporaryFile("w+b", prefix="file-{}-".format(i))
        b = ensure_bytes(json.dumps(sequence_data[i]))
        f.write(b)
        f.seek(0)
        files.append(f)

    return files


def test_file_iterator(feed_json_file):
    counter = 0
    with FeedDataFileJsonIterator(feed_json_file.name) as jsonitr:
        for record in jsonitr:
            logger.debug("Record {}".format(record))
            assert record == simple_data["data"][counter]
            counter += 1

    feed_json_file.close()
    assert counter == len(simple_data.get("data"))


def test_fileset_iterator(feed_json_file_array):
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


def test_LocalFeedDataRepo():
    tmpdir = tempfile.mkdtemp(prefix="anchoretest_repo-")
    r = LocalFeedDataRepo(metadata=LocalFeedDataRepoMetadata(data_write_dir=tmpdir))
    try:
        assert os.listdir(tmpdir) == []

        r.initialize()
        assert os.listdir(tmpdir) == ["metadata.json"]
        ts = ts = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        r.metadata.download_result = DownloadOperationResult(
            started=ts, status=FeedDownloader.State.in_progress.value, results=[]
        )
        r.flush_metadata()
        r.metadata = None
        r.reload_metadata()
        assert r.metadata.download_result.started == ts
        assert (
            r.metadata.download_result.status == FeedDownloader.State.in_progress.value
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
