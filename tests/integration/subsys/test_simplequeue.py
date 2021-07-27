import datetime

import pytest

from anchore_engine.subsys import logger, simplequeue
from anchore_engine.subsys.logger import enable_test_logging

enable_test_logging()

singleton_queue = "testq1"
multi_queue = "testq2"
std_queue = "testq3"


@pytest.fixture
def test_qs(anchore_db):
    """
    Expects to initialize the queues in an empty db, so it uses the anchore_db fixture itself to get initialized db

    :return:
    """
    global singleton_queue, multi_queue, std_queue
    simplequeue.create_queue(
        singleton_queue, max_outstanding_msgs=1, visibility_timeout=10
    )
    simplequeue.create_queue(multi_queue, max_outstanding_msgs=5, visibility_timeout=10)
    simplequeue.create_queue(std_queue, max_outstanding_msgs=0, visibility_timeout=0)


def test_std_queue(test_qs):
    """
    Simple queuing test using regular queue behavior

    :param anchore_db:
    :param test_qs:
    :return:
    """
    logger.info("Testing standard queue")
    simplequeue.enqueue(std_queue, {"key1": "value1"})

    msg = simplequeue.dequeue(std_queue)
    logger.info("Got msg: {}".format(msg))

    while msg:
        logger.info("Deleting msg {}".format(msg))
        simplequeue.delete_msg(std_queue, msg.get("receipt_handle"))
        msg = simplequeue.dequeue(std_queue)
        logger.info("Got msg: {}".format(msg))

    simplequeue.enqueue(std_queue, {"key1": "value1"})
    msg = simplequeue.dequeue(std_queue)
    logger.info("Got msg: {}".format(msg))
    assert msg is not None, "Got a None msg, expected a dict"

    msg = simplequeue.dequeue(std_queue)
    logger.info("Got msg: {}".format(msg))
    assert msg == {}, "Expected an empty dict response, got {}".format(msg)


def test_singleton_queues(test_qs):
    logger.info("Inserting")
    simplequeue.enqueue(singleton_queue, {"key1": "value1"})
    simplequeue.enqueue(singleton_queue, {"key1": "value1"})
    simplequeue.enqueue(singleton_queue, {"key1": "value1"})
    simplequeue.enqueue(singleton_queue, {"key1": "value1"})

    logger.info("Reading back")

    msg = simplequeue.dequeue(singleton_queue)
    logger.info("Got msg: {}".format(msg))

    while msg:
        logger.info("Deleting msg {}".format(msg))
        simplequeue.delete_msg(singleton_queue, msg.get("receipt_handle"))
        msg = simplequeue.dequeue(singleton_queue)
        logger.info("Got msg: {}".format(msg))


def test_multi_queues(test_qs):
    logger.info("Inserting")
    simplequeue.enqueue(multi_queue, {"key1": "value1"})
    simplequeue.enqueue(multi_queue, {"key2": "value2"})
    simplequeue.enqueue(multi_queue, {"key3": "value3"})
    simplequeue.enqueue(multi_queue, {"key4": "value4"})
    simplequeue.enqueue(multi_queue, {"key5": "value5"})

    logger.info("Reading back")
    counter = 0
    msgs = []
    msg = True
    while msg:
        logger.info("Got msg: {}".format(msg))
        msg = simplequeue.dequeue(multi_queue)
        if not msg:
            logger.info("No msg received")
            logger.info("Counter = {}".format(counter))
            if counter > 0 and len(msgs) > 0:
                for m in msgs:
                    logger.info("Deleting msg {}".format(m))
                    simplequeue.delete_msg(multi_queue, m.get("receipt_handle"))
                msgs = []
                counter = 0
            else:
                break
            msg = True
        else:
            msgs.append(msg)
            counter += 1

    resp = simplequeue.delete_msg(multi_queue, "blah")
    assert not resp, "Expected a false/None response, got: {}".format(resp)


def test_visibility_timeout(test_qs):
    simplequeue.enqueue(multi_queue, {"key00001": "value0001"})

    msg = simplequeue.dequeue(multi_queue, visibility_timeout=5)
    max_approx_timeout = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)

    min_approx_timeout = max_approx_timeout + datetime.timedelta(seconds=-1)
    assert (
        min_approx_timeout <= msg["visible_at"] <= max_approx_timeout
    ), "Msg visible time, {}, outside expected range {} - {}".format(
        msg.get("visible_at"), min_approx_timeout, max_approx_timeout
    )

    logger.info("Updating timeout: {}".format(msg["visible_at"].isoformat()))
    ts = simplequeue.update_visibility_timeout(
        multi_queue, receipt_handle=msg["receipt_handle"], visibility_timeout=20
    )

    logger.info("Updated timeout: {}".format(ts))
    assert (
        ts is not None
    ), "Expected a non-None value, got None for updated timeout after viz timeout update"

    simplequeue.delete_msg(multi_queue, receipt_handle=msg["receipt_handle"])
