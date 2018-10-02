import datetime
import unittest

from anchore_engine.db import db_locks, initialize, session_scope, Lease, db_queue
from anchore_engine.subsys import logger, simplequeue
from anchore_engine.subsys.logger import enable_bootstrap_logging

enable_bootstrap_logging()

conn_str = 'postgres+pg8000://postgres:postgres@localhost:54320/postgres'


def init():
    config = {
        'credentials':
            {'database':
                 {'db_connect': conn_str}
            }
    }
    initialize(localconfig=config)


class TestSimpleQueue(unittest.TestCase):
    singleton_queue = 'testq1'
    multi_queue = 'testq2'
    std_queue = 'testq3'

    @classmethod
    def setUpClass(cls):
        init()
        simplequeue.create_queue(cls.singleton_queue, max_outstanding_msgs=1, visibility_timeout=10)
        simplequeue.create_queue(cls.multi_queue, max_outstanding_msgs=5, visibility_timeout=10)
        simplequeue.create_queue(cls.std_queue, max_outstanding_msgs=0, visibility_timeout=0)


    def test_std_queue(self):
        print('Testing standard queue')
        simplequeue.enqueue(self.std_queue, {'key1': 'value1'})

        msg = simplequeue.dequeue(self.std_queue)
        print(('Got msg: {}'.format(msg)))

        while msg:
            print(('Deleting msg {}'.format(msg)))
            simplequeue.delete_msg(self.std_queue, msg.get('receipt_handle'))
            msg = simplequeue.dequeue(self.std_queue)
            print(('Got msg: {}'.format(msg)))


        simplequeue.enqueue(self.std_queue, {'key1': 'value1'})
        msg = simplequeue.dequeue(self.std_queue)
        print(('Got msg: {}'.format(msg)))
        self.assertIsNotNone(msg)
        msg = simplequeue.dequeue(self.std_queue)
        print(('Got msg: {}'.format(msg)))
        self.assertEqual(msg, {})


    def test_singleton_queues(self):
        print('Inserting')
        simplequeue.enqueue(self.singleton_queue, {'key1': 'value1'})
        simplequeue.enqueue(self.singleton_queue, {'key1': 'value1'})
        simplequeue.enqueue(self.singleton_queue, {'key1': 'value1'})
        simplequeue.enqueue(self.singleton_queue, {'key1': 'value1'})

        print('Reading back')

        msg = simplequeue.dequeue(self.singleton_queue)
        print(('Got msg: {}'.format(msg)))

        while msg:
            print(('Deleting msg {}'.format(msg)))
            simplequeue.delete_msg(self.singleton_queue, msg.get('receipt_handle'))
            msg = simplequeue.dequeue(self.singleton_queue)
            print(('Got msg: {}'.format(msg)))

    def test_multi_queues(self):
        print('Inserting')
        simplequeue.enqueue(self.multi_queue, {'key1': 'value1'})
        simplequeue.enqueue(self.multi_queue, {'key2': 'value2'})
        simplequeue.enqueue(self.multi_queue, {'key3': 'value3'})
        simplequeue.enqueue(self.multi_queue, {'key4': 'value4'})
        simplequeue.enqueue(self.multi_queue, {'key5': 'value5'})

        print('Reading back')
        counter = 0
        msgs = []
        msg = True
        while msg:
            print(('Got msg: {}'.format(msg)))
            msg = simplequeue.dequeue(self.multi_queue)
            if not msg:
                print('No msg received')
                print(('Counter = {}'.format(counter)))
                if counter > 0 and len(msgs) > 0:
                    for m in msgs:
                        print(('Deleting msg {}'.format(m)))
                        simplequeue.delete_msg(self.multi_queue, m.get('receipt_handle'))
                    msgs = []
                    counter = 0
                else:
                    break
                msg = True
            else:
                msgs.append(msg)
                counter += 1

        self.assertFalse(simplequeue.delete_msg(self.multi_queue, 'blah'))

    def test_visibility_timeout(self):
        simplequeue.enqueue(self.multi_queue, {'key00001': 'value0001'})

        msg = simplequeue.dequeue(self.multi_queue, visibility_timeout=5)
        approx_timeout = datetime.datetime.utcnow() + datetime.timedelta(seconds=5)

        self.assertLessEqual(msg['visible_at'], approx_timeout)
        self.assertGreaterEqual(msg['visible_at'], approx_timeout + datetime.timedelta(seconds=-1))

        print(('Updating timeout: {}'.format(msg['visible_at'].isoformat())))
        ts = simplequeue.update_visibility_timeout(self.multi_queue, receipt_handle=msg['receipt_handle'], visibility_timeout=20)
        print(('Updated timeout: {}'.format(ts)))
        self.assertIsNotNone(ts)
        simplequeue.delete_msg(self.multi_queue, receipt_handle=msg['receipt_handle'])


if __name__ == '__main__':
    unittest.main()
