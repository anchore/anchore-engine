import hashlib
import io
import tempfile
from contextlib import contextmanager
from os import path
from types import TracebackType
from typing import Generator, Optional, Type


class ChecksumMismatchError(Exception):
    def __init__(self, expected_checksum, actual_checksum):
        super().__init__(
            f"GrypeDB Checksum does not match! Expected: {expected_checksum}, Actual: {actual_checksum}"
        )


class GrypeDBFile:
    @classmethod
    def verify_integrity(cls, file_data: bytes, expected_checksum: str):
        actual_checksum = hashlib.sha256(file_data).hexdigest()
        if actual_checksum != expected_checksum:
            raise ChecksumMismatchError

    def __init__(self, parent_directory_path: str):
        self.root_directory = parent_directory_path
        self._file_path: Optional[str] = None

    @contextmanager
    def create_file(self, checksum: str) -> Generator[io.BufferedIOBase, None, None]:
        self._file_path = path.join(self.root_directory, f"{checksum}.tar.gz")
        temp_file = open(self._file_path, "wb")
        try:
            yield temp_file
        finally:
            temp_file.close()
            self._verify_integrity(checksum)

    def _verify_integrity(self, expected_checksum):
        with open(self._file_path, "rb") as temp_file:
            data = temp_file.read()
        self.verify_integrity_bytes(data, expected_checksum)

    @property
    def path(self) -> Optional[str]:
        return self._file_path


class GrypeDBStorage:
    def __init__(self):
        self.directory: Optional[tempfile.TemporaryDirectory] = None
        self.grypedbfile: Optional[GrypeDBFile] = None

    def _create(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.grypedbfile = GrypeDBFile(self.directory.name)

    def __enter__(self) -> GrypeDBFile:
        if not self.directory:
            self._create()
        return self.grypedbfile

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self._delete()

    def _delete(self) -> None:
        if self.directory:
            self.directory.cleanup()
            self.directory = None

    def __del__(self) -> None:
        self._delete()
