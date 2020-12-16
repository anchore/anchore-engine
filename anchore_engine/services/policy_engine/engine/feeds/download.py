import json
import enum
import os
import datetime
import shutil
import typing

from anchore_engine.utils import mapped_parser_item_iterator
from anchore_engine.services.policy_engine.engine.feeds import IFeedSource
from anchore_engine.common.schemas import (
    LocalFeedDataRepoMetadata,
    DownloadOperationConfiguration,
    DownloadOperationResult,
    GroupDownloadOperationConfiguration,
    FeedAPIGroupRecord,
    FeedAPIRecord,
    GroupDownloadResult,
)

from anchore_engine.subsys import logger

from anchore_engine.utils import ensure_bytes, timer

FEED_DATA_ITEMS_PATH = "data.item"


class LocalFeedDataRepo(object):
    """
    A local-host structure holding feed data as well as a metadata store that can be read from or written-to like a feed
    """

    @classmethod
    def from_disk(cls, path):
        """
        Create a new repo instance from an existing one on disk, loading metadata
        :param path:
        :return:
        """
        r = LocalFeedDataRepo(metadata=LocalFeedDataRepoMetadata(data_write_dir=path))
        r.reload_metadata()
        return r

    def __init__(self, metadata: LocalFeedDataRepoMetadata):
        self.metadata = metadata
        if self.metadata:
            self.root_dir = self.metadata.data_write_dir
            if not self.root_dir:
                raise ValueError("data_write_dir must be set in metadata")
            self.metadata_file_path = os.path.join(self.root_dir, "metadata.json")
        else:
            raise ValueError("Must have valid metadata object")

    def initialize(self):
        """
        Initialize the on-disk structures if not already present. If structure and metadata is found, this is a no-op
        :return:
        """
        if not self.has_root():
            self._init_root()

        if not self.has_metadata():
            self._init_metadata()

        self.reload_metadata()

    def _init_root(self):
        logger.debug("Initializing local data repo root at {}".format(self.root_dir))
        os.makedirs(self.root_dir, exist_ok=False)

    def _init_metadata(self):
        with open(self.metadata_file_path, "w") as f:
            json.dump(self.metadata.to_json(), f)

    def has_root(self):
        return os.path.exists(self.root_dir) and os.path.isdir(self.root_dir)

    def has_metadata(self):
        return os.path.exists(self.metadata_file_path)

    def flush_metadata(self):
        """
        Flushes the metadata in the 'metadata' property to disk, overwriting any old values

        :return:
        """

        with open(self.metadata_file_path, "w") as f:
            json.dump(self.metadata.to_json(), f)

    def reload_metadata(self):
        """
        Re-loads the metadata from the disk to the local instance, overwriting any local value in memory

        :return:
        """
        with open(self.metadata_file_path) as f:
            self.metadata = LocalFeedDataRepoMetadata.from_json(json.load(f))

    def write_data(self, feed, group, chunk_id, data: bytes):
        write_dir = os.path.join(self.root_dir, feed, group)

        os.makedirs(write_dir, exist_ok=True)

        outfile = os.path.join(write_dir, str(chunk_id))
        with open(outfile, "w+b") as f:
            f.write(data)

    def write_json(self, feed, group, chunk_id, data):
        b = ensure_bytes(json.dumps(data))
        self.write_data(feed, group, chunk_id, b)

    def read(self, feed, group, start_index):
        """
        Returns an iterator thru the records of the feed group, starting at the given index offset of the entire record set

        :param feed:
        :param group:
        :param start_index:
        :return:
        """

        files = [
            os.path.join(self.root_dir, feed, group, str(x))
            for x in sorted(
                int(y) for y in os.listdir(os.path.join(self.root_dir, feed, group))
            )
        ]
        return FileListJsonIterator(files, start_index)

    def teardown(self):
        shutil.rmtree(self.root_dir)


class FeedDataFileJsonIterator(object):
    """
    Iterator for the objects within a single page of feed data.
    A page is a json object with a few keys:

    {
      "next_token": <str>,
      "since": <str>,
      "data": [ <array of obj> ]
    }

    """

    def __init__(self, path):
        self.record_index = 0
        self.path = path
        self.json_itr = None
        self.fd = None

    def _init_fp(self):
        self.fd = open(self.path, "rb")
        self.json_itr = mapped_parser_item_iterator(self.fd, FEED_DATA_ITEMS_PATH)

    def __enter__(self):
        self._init_fp()
        return self

    def __iter__(self):
        if not self.json_itr:
            self._init_fp()

        return self

    def __next__(self):
        if self.json_itr is None:
            raise Exception("File iterator not initialized")

        self.record_index += 1
        return self.json_itr.__next__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            self.fd.close()


class FileListJsonIterator(object):
    """
    Iterator that will return json objects from the files listed in order handling the open/close between files.
    Supports an initial offset for the read.

    """

    def __init__(self, ordered_path_list: list, start_index: int):
        """

        :param ordered_path_list:
        :param start_index: the index of the first record to return
        """
        self.files = ordered_path_list
        self.record_start_index = start_index
        self.total_record_index = 0
        self.current_file_index = 0
        self.current_file = None
        self.file_itr = None

    def __iter__(self):
        self._init_itr()
        return self

    def _init_itr(self):
        if self.current_file_index < len(self.files):
            # TODO: make this debug? Kinda useful at info
            logger.info(
                "Reading feed data from file {}".format(
                    self.files[self.current_file_index]
                )
            )
            self.file_itr = iter(
                FeedDataFileJsonIterator(self.files[self.current_file_index])
            )
        else:
            self.file_itr = None
            raise StopIteration()

    def __next__(self):
        while self.file_itr is not None:
            try:
                return self.file_itr.__next__()
            except StopIteration as e:
                self.current_file_index += 1
                self._init_itr()
        else:
            raise StopIteration()


def _download_start_metadata() -> DownloadOperationResult:
    return DownloadOperationResult(
        started=datetime.datetime.utcnow(),
        status=FeedDownloader.State.in_progress.value,
        results=[],
    )


def _group_download_start_metadata(group: GroupDownloadOperationConfiguration):
    return GroupDownloadResult(
        feed=group.feed,
        group=group.group,
        total_records=0,
        status=FeedDownloader.State.in_progress.value,
        started=datetime.datetime.utcnow(),
    )


def _update_download_failed(
    conf: GroupDownloadResult, record_count: int
) -> GroupDownloadResult:
    conf.status = FeedDownloader.State.failed.value
    conf.ended = datetime.datetime.utcnow()
    conf.total_records = record_count
    return conf


def _update_download_complete(
    conf: GroupDownloadResult, record_count: int
) -> GroupDownloadResult:
    conf.status = FeedDownloader.State.complete.value
    conf.ended = datetime.datetime.utcnow()
    conf.total_records = record_count
    return conf


class FeedDownloader(object):
    """
    Fetch feed data and store it on the local disk for further processing
    """

    class State(enum.Enum):
        in_progress = "in_progress"
        complete = "complete"
        failed = "failed"

    def __init__(
        self,
        download_root_dir: str,
        config: DownloadOperationConfiguration,
        client: IFeedSource,
        fetch_all: bool = False,
    ):
        """
        :param config: configuration for doing the fetch
        :param client: the client to use to pull data
        :param force_full_flush: if true, ignore last sync timestamps and fetch all data from source
        """
        if not config:
            raise ValueError("Must have non-None config")
        if not download_root_dir:
            raise ValueError("Must have non-None download root directory path")

        self.config = config
        op_dir = os.path.join(download_root_dir, self.config.uuid)
        logger.debug(
            "Initializing downloader for operation {}. Will write to path: {}".format(
                config.uuid, op_dir
            )
        )
        repo_meta = LocalFeedDataRepoMetadata(
            download_configuration=config, data_write_dir=op_dir
        )
        self.local_repo = LocalFeedDataRepo(metadata=repo_meta)

        self.service_client = client
        self.fetch_all = fetch_all

    def execute(self, feed_name=None, group_name=None) -> LocalFeedDataRepo:
        """
        Uses the parent method to get the full set of data and spool it to disk, then feeds it to the caller one page at a time.

        :param feed:
        :param group:
        :param since:
        :param next_token:
        :return:
        """

        try:
            self.local_repo.initialize()
            self.local_repo.metadata.download_result = _download_start_metadata()
            self.local_repo.flush_metadata()
        except:
            logger.debug_exception(
                "Could not initialize the feed data download location: {}. Failing fetch attempt".format(
                    self.local_repo.root_dir
                )
            )
            raise

        groups_failed = 0
        try:
            for group in self.config.groups:
                if (
                    feed_name
                    and group.feed != feed_name
                    or (group_name and group_name != group.group)
                ):
                    # Skip groups that don't match if a specific group was requested
                    logger.debug(
                        "Download configuration has record for group {}/{} but only {}/{} requested, so skipping".format(
                            group.feed, group.group, feed_name, group_name
                        )
                    )
                    continue

                meta = _group_download_start_metadata(group)
                record_count = 0
                try:
                    self.local_repo.metadata.download_result.results.append(meta)
                    self.local_repo.flush_metadata()

                    logger.info(
                        "Downloading data for group {}/{}".format(
                            group.feed, group.group
                        )
                    )
                    with timer(
                        "data download for group {}/{}".format(group.feed, group.group),
                        log_level="info",
                    ):
                        for count in self._fetch_group_data(group):
                            record_count += count
                            meta.total_records = record_count
                            self.local_repo.flush_metadata()

                    _update_download_complete(meta, record_count)
                except:
                    logger.exception(
                        "Error downloading data for group {}/{}".format(
                            group.feed, group.group
                        )
                    )
                    # Ensure consistent state for next phase, so cleanup anything failed
                    _update_download_failed(meta, record_count)

                    groups_failed += 1
                finally:
                    self.local_repo.flush_metadata()

            if groups_failed > 0:
                self.local_repo.metadata.download_result.status = (
                    FeedDownloader.State.failed.value
                )
            else:
                self.local_repo.metadata.download_result.status = (
                    FeedDownloader.State.complete.value
                )
        except:
            logger.debug_exception(
                "Error fetching feed data, setting status to failed for operation {}".format(
                    self.config.uuid
                )
            )
            self.local_repo.metadata.download_result.status = (
                FeedDownloader.State.failed.value
            )
            raise
        finally:
            logger.info("Feed data download process ending")
            self.local_repo.metadata.download_result.ended = datetime.datetime.utcnow()
            self.local_repo.flush_metadata()

        return self.local_repo

    def _fetch_group_data(
        self, group: GroupDownloadOperationConfiguration
    ) -> typing.Iterable:
        """
        Execute the download and write the data into the local repo location for the group

        :param group:
        :return: generator for the record count of each chunk as it is downloaded
        """

        get_next = True
        next_token = None
        chunk_number = 0
        count = 0
        since = group.parameters.since if not self.fetch_all else None

        while get_next:
            logger.info(
                "Downloading page {} of feed data for feed group: {}/{}".format(
                    chunk_number, group.feed, group.group
                )
            )
            group_data = self.service_client.get_feed_group_data(
                group.feed, group.group, since=since, next_token=next_token
            )
            get_next = bool(group_data.next_token)
            next_token = group_data.next_token
            count += group_data.record_count
            if group_data.data is not None:
                self.local_repo.write_data(
                    group.feed, group.group, chunk_number, ensure_bytes(group_data.data)
                )
            chunk_number += 1
            yield group_data.record_count

        logger.info(
            "Completed data download of for feed group: {}/{}. Total pages: {}".format(
                group.feed, group.group, chunk_number
            )
        )
