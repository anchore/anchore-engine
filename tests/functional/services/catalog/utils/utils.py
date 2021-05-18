import logging
from typing import Dict

from tests.functional.services.catalog.utils.api import objects
from tests.functional.services.utils import http_utils


def add_or_replace_document(bucket: str, archiveid: str, object: Dict) -> None:
    """
    Deletes document from object store if it exists before inserting it.
    :param bucket: bucket name
    :type bucket: str
    :param archiveid: archive ID
    :type archiveid: str
    :param object: object to insert
    :type object: Dict
    """
    try:
        objects.delete_document(bucket, archiveid)
    except http_utils.RequestFailedError as err:
        logging.error(err)
    objects.add_document(bucket, archiveid, object)
