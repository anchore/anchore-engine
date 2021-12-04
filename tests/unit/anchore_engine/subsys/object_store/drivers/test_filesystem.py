import os

import hashlib

import shutil

import pytest

from anchore_engine.subsys.object_store import FilesystemObjectStorageDriver


class TestFilesystemObjectStorageDriver:

    __archive_data_dir__ = "/tmp/anchore-engine-unit-test-filesystem"

    @pytest.fixture(autouse=True)
    def cleanup_archive_data_dir(self):
        yield
        shutil.rmtree(self.__archive_data_dir__)

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {"userId": "dakaneye", "bucket": "bucket", "key": "key"}, id="success"
            )
        ],
    )
    def test_uri_for(self, param):
        driver = FilesystemObjectStorageDriver(
            config={"archive_data_dir": self.__archive_data_dir__}
        )
        expected_path = "file://{}".format(
            driver._get_archive_filepath(param["userId"], param["bucket"], param["key"])
        )
        assert (
            driver.uri_for(param["userId"], param["bucket"], param["key"])
            == expected_path
        )

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {"uri": "/usr/local/bin/grype", "expected": "/usr/local/bin/grype"},
                id="unix-path",
            ),
            pytest.param(
                {"uri": "C:\\Documents\\UnitTest", "expected": "\\Documents\\UnitTest"},
                id="windows-path",
            ),
            pytest.param({"uri": "https://www.anchore.com", "expected": ""}, id="url"),
        ],
    )
    def test_parse_uri(self, param):
        driver = FilesystemObjectStorageDriver(
            config={"archive_data_dir": self.__archive_data_dir__}
        )
        actual_path = driver._parse_uri(param["uri"])
        assert actual_path == param["expected"]

    @pytest.mark.parametrize(
        "param",
        [
            pytest.param(
                {
                    "userId": "dakaneye",
                    "bucket": "unittest",
                    "key": "filesystemobjectstoragedriver",
                },
                id="success",
            )
        ],
    )
    def test_get_archive_filepath(self, param):
        driver = FilesystemObjectStorageDriver(
            config={"archive_data_dir": self.__archive_data_dir__}
        )
        actual_fp = driver._get_archive_filepath(
            param["userId"], param["bucket"], param["key"]
        )

        # Since hashes are dynamically computed, but they're md5 we can just do the same thing as the method to verify it's printing the expected thing
        expected_filehash = hashlib.new(
            "md5", param["key"].encode("utf8"), usedforsecurity=False
        ).hexdigest()
        expected_fkey = expected_filehash[0:2]
        expected_path = os.path.join(
            os.path.join(
                self.__archive_data_dir__,
                hashlib.new(
                    "md5", param["userId"].encode("utf8"), usedforsecurity=False
                ).hexdigest(),
                param["bucket"],
                expected_fkey,
            ),
            expected_filehash + ".json",
        )
        assert actual_fp == expected_path

    def test_load_content(self):
        driver = FilesystemObjectStorageDriver(
            config={"archive_data_dir": self.__archive_data_dir__}
        )
        testfilename = self.__archive_data_dir__ + "/loadcontenttest"
        file_contents = "this is a unit test"
        with open(testfilename, "a") as f:
            f.write(file_contents)

        actual_loaded_content = driver._load_content(testfilename)
        assert actual_loaded_content == bytes(file_contents, "utf8")
