import hashlib
import io
import tempfile
from contextlib import contextmanager
from os import path
from types import TracebackType
from typing import Generator, Optional, Type


class ChecksumMismatchError(Exception):
    """
    Exception raised when file data is corrupt (calculated checksum does not match expected value)

    :param expected_checksum: the expected checksum value
    :type expected_checksum: str
    :param actual_checksum: the calculated checksum value
    :type actual_checksum: str
    """

    def __init__(self, expected_checksum: str, actual_checksum: str) -> None:
        super().__init__(
            f"GrypeDB Checksum does not match! Expected: {expected_checksum}, Actual: {actual_checksum}"
        )


class GrypeDBFile:
    """
    Class for reading/writing an individual grype db file. Should only be instantiated by GrypeDBStorage.

    :param parent_directory_path: The path of the parent directory (temp dir for caching Grype DB)
    :type parent_directory_path: str
    """

    @classmethod
    def verify_integrity(cls, file_data: bytes, expected_checksum: str) -> None:
        """
        Classmethod, calculates sha256 checksum of bytes passed in against provided expected checksum.
        Raises ChecksumMismatchError if not equivalent.

        :param file_data: the raw file data
        :type file_data: bytes
        :param expected_checksum: expected sha256 checksum value
        :type expected_checksum: str
        """
        actual_checksum = "sha256:{}".format(hashlib.sha256(file_data).hexdigest())
        if actual_checksum != expected_checksum:
            raise ChecksumMismatchError(expected_checksum, actual_checksum)

    def __init__(self, parent_directory_path: str) -> None:
        self.root_directory = parent_directory_path
        self._file_path: Optional[str] = None

    @contextmanager
    def create_file(self, checksum: str) -> Generator[io.BufferedIOBase, None, None]:
        """
        Context manager, yields open file handle to write data to and closes it on context exit.

        :param checksum: the sha256 checksum of the file, will also be used as file name (with .tar.gz ext)
        :type checksum: str
        :return: generator yields file handle opened in "wb" mode
        :rtype: Generator[io.BufferedIOBase, None, None]
        """
        self._file_path = path.join(self.root_directory, f"{checksum}.tar.gz")
        temp_file = open(self._file_path, "wb")
        try:
            yield temp_file
        finally:
            temp_file.close()
            self._verify_integrity(checksum)

    def _verify_integrity(self, expected_checksum: str) -> None:
        """
        Calculates sha256 checksum of the file created by `create_file()` and compares against provided expected value.
        Raises ChecksumMismatchError if not equivalent.

        :param expected_checksum: expected sha256 checksum value
        :type expected_checksum: str
        """
        with open(self._file_path, "rb") as temp_file:
            data = temp_file.read()
        self.verify_integrity(data, expected_checksum)

    @property
    def path(self) -> Optional[str]:
        """
        Getter for path of file created by `create_file()`

        :return: path of the file created if created, otherwise None
        :rtype: Optional[str]
        """
        return self._file_path


class GrypeDBStorage:
    """
    Disk cache for Grype DB.
    Context manager wrapping tempfile.TemporaryDirectory.
    Abstracts actual temp dir creation/destruction logic and returns instance of GrypeDBFile on context entry.
    """

    def __init__(self):
        self.directory: Optional[tempfile.TemporaryDirectory] = None
        self.grypedbfile: Optional[GrypeDBFile] = None

    def _create(self) -> None:
        """
        Create the temp dir and instantiate the GrypeDBFile
        """
        self.directory = tempfile.TemporaryDirectory()
        self.grypedbfile = GrypeDBFile(self.directory.name)

    def __enter__(self) -> GrypeDBFile:
        """
        Setup if the directory has not been created, yield instance of GrypeDBFile initialized with this temp dir
        location

        :return: instance of GrypeDBFile
        :rtype: GrypeDBFile
        """
        if not self.directory:
            self._create()
        return self.grypedbfile

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """
        Context exit, calls teardown

        :param exc_type: the exception type
        :type exc_type: Optional[Type[BaseException]]
        :param exc_value: the exception instance
        :type exc_value: Optional[BaseException]
        :param traceback: the traceback
        :type traceback: Optional[TracebackType]
        """
        self._delete()

    def _delete(self) -> None:
        """
        Teardown the temp dir.
        """
        if self.directory:
            self.directory.cleanup()
            self.directory = None

    def __del__(self) -> None:
        """
        Overridden deletion handler, ensures teardown of temp dir is called before deletion.
        """
        self._delete()
