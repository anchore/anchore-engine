"""
Archive Subsystem is for storing and retrieving documents (json text specifically).
Semantics are simple CRUD using namespaced defined by userId and bucket name.

Archive documents are stored in a driver-based backend with refreneces kept in the archive_document table to determine where and how to access documents and
any state necessary (e.g. for garbage collection or time-out)
"""

from .operations import get
from .operations import get_document
from .operations import get_document_meta
from .operations import put
from .operations import put_document
from .operations import initialize
from .operations import delete
from .operations import delete_document
from .operations import get_driver_list
from .operations import exists
