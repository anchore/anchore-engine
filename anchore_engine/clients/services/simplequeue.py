import json
import threading
import time

from anchore_engine.clients.services import http
from anchore_engine.subsys import logger
from anchore_engine.utils import get_threadbased_id
from anchore_engine.clients.services.internal import InternalServiceClient


class LeaseAcquisitionFailedError(Exception):
    pass


class SimpleQueueClient(InternalServiceClient):
    __service__ = 'simplequeue'

    def get_queues(self):
        return self.call_api(http.anchy_get, '/queues')

    def qlen(self, name):
        resp = self.round_robin_call_api(http.anchy_get, 'queues/{queue}/qlen', path_params={'queue': name})
        return int(resp)

    def enqueue(self, name, inobj, qcount=0, forcefirst=False):
        return self.round_robin_call_api(http.anchy_post, 'queues/{queue}', path_params={'queue': name}, query_params={'qcount': str(qcount), 'forcefirst': str(forcefirst)}, body=json.dumps(inobj))

    def delete_message(self, name, receipt_handle):
        return self.round_robin_call_api(http.anchy_delete, path='queues/{queue}', path_params={'queue': name}, query_params={'receipt_handle': receipt_handle})

    def is_inqueue(self, name, inobj):
        return self.round_robin_call_api(http.anchy_post, path='queues/{queue}/is_inqueue', path_params={'queue': name}, body=json.dumps(inobj))

    def dequeue(self, name, visibility_timeout=0, max_wait_seconds=0):
        return self.round_robin_call_api(http.anchy_get, 'queues/{queue}', path_params={'queue': name}, query_params={'wait_max_seconds': max_wait_seconds, 'visibility_timeout': visibility_timeout})

    def update_message_visibility_timeout(self, name, receipt_handle, visibility_timeout):
        return self.round_robin_call_api(http.anchy_put, 'queues/{queue}', path_params={'queue': name}, query_params={'receipt_handle': receipt_handle, 'visibility_timeout': visibility_timeout})

    def create_lease(self, lease_id):
        return self.round_robin_call_api(http.anchy_post, 'leases', query_params={'lease_id': lease_id})

    def list_leases(self):
        return self.round_robin_call_api(http.anchy_get, 'leases')

    def describe_lease(self, lease_id):
        return self.round_robin_call_api(http.anchy_get, 'leases/{lease_id}', path_params={'lease_id': lease_id})

    def acquire_lease(self, lease_id, client_id, ttl):
        return self.round_robin_call_api(http.anchy_get, 'leases/{lease_id}/acquire', path_params={'lease_id': lease_id}, query_params={'client_id': client_id, 'ttl': ttl})

    def release_lease(self, lease_id, client_id, epoch):
        return self.round_robin_call_api(http.anchy_get, 'leases/{lease_id}/release', path_params={'lease_id': lease_id}, query_params={'client_id': client_id, 'epoch': epoch})

    def refresh_lease(self, lease_id, client_id, epoch, ttl):
        return self.round_robin_call_api(http.anchy_put, 'leases/{lease_id}/ttl', path_params={'lease_id': lease_id}, query_params={'client_id': client_id, 'ttl': ttl, 'epoch': epoch})


def run_target_with_queue_ttl(user_auth, queue, visibility_timeout, target, max_wait_seconds=0, autorefresh=True, *args, **kwargs):
    """
    Run a target function with the message pulled from the queue. If autorefresh=True, then run target as a thread and periodically check
    for completion, updating the message visibility timeout to keep it fresh until the thread completes.

    The function passed as target should expect the message object as the first argument, with *args appended after in the arg list.

    :param user_auth:
    :param queue:
    :param max_wait_seconds:
    :param visibility_timeout:
    :param target:
    :param autorefresh:
    :param args:
    :param kwargs:
    :return:
    """

    client = SimpleQueueClient(as_account=user_auth[0], user=user_auth[0], password=user_auth[1])

    qobj = client.dequeue(queue, max_wait_seconds=max_wait_seconds, visibility_timeout=visibility_timeout)
    logger.debug('Got msg: {}'.format(qobj))
    if not qobj:
        logger.debug("Got empty message from queue - nothing to do")
        return(True)

    receipt_handle = qobj.get('receipt_handle')
    msg_id = qobj.get('id')
    if not receipt_handle:
        raise Exception('No receipt handle found in queue message: {}'.format(qobj))

    try:
        # Relies upon the queue configuration of 1 outstanding message (inflight) at a time for serialization across hosts
        t = time.time()
        if qobj:
            args = tuple([qobj] + list(args))
            task = threading.Thread(target=target, args=args, kwargs=kwargs)
            task.start()

            if autorefresh:
                # Run the task thread and monitor it, refreshing the task lease as needed
                while task.isAlive():
                    # If we're halfway to the timeout, refresh to have a safe buffer
                    if time.time() - t > (visibility_timeout / 2):
                        # refresh the lease
                        for i in range(3):
                            try:
                                resp = client.update_message_visibility_timeout(name=queue, receipt_handle=receipt_handle, visibility_timeout=visibility_timeout)
                                if resp:
                                    t = time.time()
                                    logger.debug('Msg with handle {} refreshed with new expiration: {}'.format(receipt_handle, resp))
                                    break
                            except Exception as e:
                                logger.exception('Error updating visibility timeout {}'.format(receipt_handle))
                        else:
                            logger.warn('Visibility refresh failed to succeed after retries. Msg {} may be replayed due to timeout'.format(msg_id))

                    task.join(timeout=1)
            else:
                # Just wait for thread to complete
                task.join()
    except Exception as err:
        logger.warn("failed to process task this cycle: " + str(err))
    finally:
        client.delete_message(queue, receipt_handle)
        # Always delete the message. Other handlers will ensure things are queued ok.


def run_target_with_lease(user_auth, lease_id, target, ttl=60, client_id=None, autorefresh=True, *args, **kwargs):
    """
    Run a handler within the context of a lease that is auto-refreshed as long as the handler runs.

    Uses a thread for the handler and a monitor to watch state and update the lease ttl.

    The leases are fairly slow to actuate, so expect to use this mechanism for longer running tasks where the lease duration should be > 10 sec

    :param user_auth:
    :param lease_id:
    :param target:
    :param args:
    :param kwargs:
    :return:
    """
    handler_thread = threading.Thread(target=target, args=args, kwargs=kwargs)

    client = SimpleQueueClient(as_account=user_auth[0], user=user_auth[0], password=user_auth[1])

    # Ensure task lease exists for acquisition and create if not found
    lease_resp = client.describe_lease(lease_id)
    if not lease_resp:
        lease_resp = client.create_lease(lease_id)

    if not lease_resp:
        raise Exception('Cannot locate or create a lease with id {}'.format(lease_id))

    # Acquire the task lease and run the task
    lease = None
    try:
        my_id = get_threadbased_id() if client_id is None else client_id
        lease = client.acquire_lease(lease_id, client_id=my_id, ttl=ttl)

        if not lease:
            logger.debug('No lease returned from service, cannot proceed with task execution. Will retry on next cycle. Lease_id: {}'.format(lease_id))
            raise LeaseAcquisitionFailedError('Could not acquire lease {} within timeout'.format(lease_id))
        else:
            logger.debug('Got lease: {}'.format(lease))

            t = time.time()
            logger.debug('Starting target={} with lease={} and client_id={}'.format(target.__name__, lease_id, lease['held_by']))
            handler_thread.start()

            if autorefresh:
                # Run the task thread and monitor it, refreshing the task lease as needed
                while handler_thread.isAlive():
                    # If we're halfway to the timeout, refresh to have a safe buffer
                    if time.time() - t > (ttl / 2):
                        # refresh the lease
                        for i in range(3):
                            try:
                                resp = client.refresh_lease(lease_id=lease['id'], client_id=lease['held_by'], epoch=lease['epoch'], ttl=ttl)
                                logger.debug('Lease {} refreshed with response: {}'.format(lease_id, resp))
                                if resp:
                                    lease = resp
                                    t = time.time()
                                    break
                            except Exception as e:
                                logger.exception('Error updating lease {}'.format(lease['id']))
                        else:
                            logger.warn('Lease refresh failed to succeed after retries. Lease {} may be lost due to timeout'.format(lease_id))

                    handler_thread.join(timeout=1)
            else:
                handler_thread.join()

            logger.debug('Target thread returned')

    except Exception as e:
        logger.warn('Attempting to get lease {} failed: {}'.format(lease_id, e))
        raise e
    finally:
        try:
            if lease:
                resp = client.release_lease(lease_id=lease['id'], client_id=lease['held_by'], epoch=lease['epoch'])
                logger.debug('Lease {} released with response: {}'.format(lease_id, resp))
            else:
                logger.debug('No lease found to release.')
        except Exception as e:
            logger.exception('Error releasing lease. Lease will expire on its own. Err: {}'.format(str(e)))
