"""
DAO layer for imports

WORK IN PROGRESS!

"""

from anchore_engine.db.entities.catalog import ImageImportOperation, ImageImportContent, ImportState
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.query import Query
import typing
import datetime

DEFAULT_PAGE_SIZE = 1001


def paginated(qry, cls, start: int, limit: int):
    """
    Helper for consistent pagination support

    Implements a simple offset-limit approach

    :param qry:
    :param cls:
    :param start:
    :param limit:
    :return:
    """

    if start > 0:
        return qry.order_by(cls.last_updated.desc()).limit(limit).offset(start)
    else:
        return qry.order_by(cls.last_updated.desc()).limit(limit)


def list_operations_by_account(db_session: Session, account: str, status: str=None, start:int=0) -> typing.List[ImageImportOperation]:
    """
    List operations
    :param db_session:
    :param account:
    :return:
    """

    assert db_session.is_active()
    assert account is not None

    qry = db_session.query(ImageImportOperation).filter(ImageImportOperation.account == account)

    if status is not None:
        qry = qry.filter(ImageImportOperation.status==status)

    qry = paginated(qry, ImageImportOperation, start, DEFAULT_PAGE_SIZE)
    ops = qry.all()

    return [x.to_detached() for x in ops]


def create_operation(db_session: Session, obj: ImageImportOperation):
    """
    Add the given operation object to the session and flushed, but not committed

    :param db_session:
    :param obj:
    :return:
    """

    db_session.add(obj)
    db_session.flush()
    return obj


def delete_operation(db_session: Session, account: str, operation_id: str):
    """
    Lookup and delete the operation with given ID if it is in the given account.

    Raises an exception if no entity matching the identifiers is found.

    :param db_session:
    :param account:
    :param operation_id:
    :return:
    """

    op = db_session.query(ImageImportOperation).filter(ImageImportOperation.account == account, ImageImportOperation.uuid == operation_id).one()
    db_session.delete(op)
    db_session.flush()


def ready_for_gc(db_session):
    """
    Return a list of operation Ids ready for garbage collection. Only returns a list of ids.

    :return: list of string IDs
    """

    ids = db_session.query(ImageImportOperation.uuid).filter(ImageImportOperation.status.in_([ImportState.complete, ImportState.invalidated, ImportState.failed, ImportState.expired])).all()
    return ids


def mark_expired(db_session):
    """
    Return a list of operation Ids ready for garbage collection. Only returns a list of ids.

    :return: list of string IDs
    """
    expired_ids = []

    for op in db_session.query(ImageImportOperation.uuid).filter(ImageImportOperation.expires_at <= datetime.datetime.utcnow()):
        op.status = ImportState.expired
        expired_ids.append(op.uuid)

    db_session.flush()

    return expired_ids


def update_operation_status(db_session, operation_id: str, new_status: ImportState):
    """

    :param db_session:
    :param operation_id:
    :param new_status:
    :return:
    """

    op = db_session.query(ImageImportOperation).filter(ImageImportOperation.uuid == operation_id).one_or_none()
    op.status = new_status

    return op



