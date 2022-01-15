from anchore_engine import db
from anchore_engine.db import db_queue

queues = {}
queues_persist_files = {}


def create_queue(name, max_outstanding_msgs=0, visibility_timeout=0):
    try:
        with db.session_scope() as dbsession:
            db_queue.create(
                name,
                "system",
                max_outstanding_msgs=max_outstanding_msgs,
                visibility_timeout=visibility_timeout,
                session=dbsession,
            )
    except Exception as err:
        raise err

    return True


def get_queuenames():
    ret = []

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.get_queuenames("system", session=dbsession)
    except Exception as err:
        raise err

    return ret


def get_queue(name):
    try:
        with db.session_scope() as dbsession:
            ret = db_queue.get_queue(name, "system", session=dbsession)
            return ret
    except Exception as err:
        raise err


def qlen(name):
    queuenames = get_queuenames()

    if name not in queuenames:
        return 0

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.get_qlen(name, "system", session=dbsession)
    except Exception as err:
        raise err

    return ret


def enqueue(name, inobj, qcount=0, forcefirst=False):
    ret = {}

    queuenames = get_queuenames()

    if name in queuenames:
        try:
            with db.session_scope() as dbsession:
                ret = db_queue.enqueue(
                    name,
                    "system",
                    inobj,
                    qcount=qcount,
                    priority=forcefirst,
                    session=dbsession,
                )
        except Exception as err:
            raise err

    return ret


def dequeue(name, visibility_timeout=None):
    """
    Get a message off the named queue with optional visibility timeout if the queue supports it. If the specific queue
    does have visibility_timeouts enabled it will be ignored.

    """
    ret = {}
    queue = get_queue(name)
    if queue is None:
        return None

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.dequeue(
                name, "system", visibility_timeout=visibility_timeout, session=dbsession
            )
        return ret
    except Exception as err:
        raise err


def update_visibility_timeout(name, receipt_handle, visibility_timeout):
    """
    Reset the visibility timeout of the message with given receipt handle to the given visibility timeout value

    :param name:
    :param receipt_handle:
    :param visibility_timeout:
    :return:
    """

    ret = {}
    queue = get_queue(name)
    if queue is None:
        return None

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.update_visibility_by_handle(
                name, "system", receipt_handle, visibility_timeout, session=dbsession
            )
        return ret
    except Exception as err:
        raise err


def delete_msg(name, receipt_handle):
    ret = False
    queue = get_queue(name)

    if not queue:
        return None

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.delete_msg_by_handle(
                name, "system", receipt_handle, session=dbsession
            )
    except Exception as err:
        raise err

    return ret


def is_inqueue(name, inobj):
    ret = {}
    queuenames = get_queuenames()

    if name not in queuenames:
        return {}

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.is_inqueue(name, "system", inobj, session=dbsession)
    except Exception as err:
        raise err

    return ret


def update_queueid(name, src_queueId, dst_queueId):
    ret = False

    queuenames = get_queuenames()

    if name not in queuenames:
        return ret

    try:
        with db.session_scope() as dbsession:
            ret = db_queue.update_queueid(
                name,
                "system",
                src_queueId=src_queueId,
                dst_queueId=dst_queueId,
                session=dbsession,
            )
    except Exception as err:
        raise err

    return ret
