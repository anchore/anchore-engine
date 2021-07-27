"""
Object storage subsystem is for storing and retrieving documents (json text specifically).
Semantics are simple CRUD using namespaced defined by userId and bucket name.

Archive documents are stored in a driver-based backend with refreneces kept in the archive_document table to determine where and how to access documents and
any state necessary (e.g. for garbage collection or time-out)
"""

from anchore_engine.subsys.object_store.drivers import (
    DbDriver,
    FilesystemObjectStorageDriver,
    ObjectStorageDriver,
    ObjectStorageDriverMeta,
    S3ObjectStorageDriver,
    SwiftObjectStorageDriver,
    interface,
)
from anchore_engine.subsys.object_store.manager import get_manager, initialize
