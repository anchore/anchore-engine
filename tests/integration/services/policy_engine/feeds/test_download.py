"""
Tests the feed data fetcher
"""

import tempfile
import os
import uuid

from tests.utils import init_test_logging
from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.engine.feeds.download import FeedDownloader
from anchore_engine.services.policy_engine.engine.feeds.schemas import (
    DownloadOperationConfiguration,
    GroupDownloadOperationConfiguration,
    GroupDownloadOperationParams,
    LocalFeedDataRepoMetadata,
)
from anchore_engine.services.policy_engine.engine.feeds.client import get_client
from anchore_engine.utils import ensure_bytes, timer

init_test_logging(level="debug")

ANCHOREIO_URI = "https://ancho.re/v1/service/feeds"


def test_feed_downloader():
    """
    Requires network access to the public feed service ancho.re

    :return:
    """

    groups_to_sync = [
        GroupDownloadOperationConfiguration(
            feed="vulnerabilities",
            group="alpine:3.7",
            parameters=GroupDownloadOperationParams(since=None),
        ),
        GroupDownloadOperationConfiguration(
            feed="vulnerabilities",
            group="alpine:3.8",
            parameters=GroupDownloadOperationParams(since=None),
        ),
        # GroupDownloadOperationConfiguration(feed='nvdv2', group='nvdv2:cves', parameters=GroupDownloadOperationParams(since=None))
    ]
    dl_conf = DownloadOperationConfiguration(
        groups=groups_to_sync, uuid=uuid.uuid4().hex, source_uri=ANCHOREIO_URI
    )
    tmpdir = tempfile.mkdtemp(prefix="anchoretest_repo-")
    data_repo = None
    try:
        client = get_client(
            ANCHOREIO_URI,
            user=("something", "something"),
            conn_timeout=1,
            read_timeout=30,
        )
        fetcher = FeedDownloader(
            download_root_dir=tmpdir, config=dl_conf, client=client, fetch_all=False
        )

        with timer("feed download", log_level="info"):
            data_repo = fetcher.execute()

        assert data_repo is not None
        assert data_repo.root_dir.startswith(tmpdir)
        assert data_repo.metadata.data_write_dir.startswith(tmpdir)
        assert os.path.isdir(data_repo.metadata.data_write_dir)
        assert os.path.isdir(data_repo.root_dir)
        assert len(os.listdir(tmpdir)) > 0

        count = 0
        with timer("alpine 3.8 iterate", log_level="info"):
            for _ in data_repo.read("vulnerabilities", "alpine:3.8", 0):
                count += 1

        assert count == sum(
            [
                x.total_records
                for x in data_repo.metadata.download_result.results
                if x.feed == "vulnerabilities" and x.group == "alpine:3.8"
            ]
        )

        with timer("alpine 3.7 iterate", log_level="info"):
            for _ in data_repo.read("vulnerabilities", "alpine:3.7", 0):
                count += 1

        assert count == sum(
            [x.total_records for x in data_repo.metadata.download_result.results]
        )

    finally:
        logger.info("Cleaning up temp dir")
        if data_repo:
            data_repo.teardown()
