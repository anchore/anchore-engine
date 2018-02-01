import json
import threading
import thread
import uuid
import os
import platform
import time

from anchore_engine.clients import http
import anchore_engine.clients.common
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger


localconfig = None
headers = {'Content-Type': 'application/json'}


def get_queues(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = []
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def qlen(userId, name):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = 0

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [name, "qlen"]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)
    ret = int(ret)

    return (ret)


def enqueue(userId, name, inobj, qcount=0, forcefirst=False):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = inobj

    url_postfix = [name, "?qcount=" + str(qcount) + "&forcefirst=" + str(forcefirst)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_post, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return (ret)


def delete_message(userId, name, receipt_handle):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = ''

    url_postfix = [name, "?receipt_handle=" + receipt_handle]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_delete, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return (ret)


def is_inqueue(userId, name, inobj):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = inobj

    url_postfix = [name, 'is_inqueue']
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_post, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return (ret)


def dequeue(userId, name, visibility_timeout=0, max_wait_seconds=0):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = {}

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [name, "?wait_max_seconds={}&visibility_timeout={}".format(max_wait_seconds, visibility_timeout)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def update_message_visibility_timeout(userId, name, receipt_handle, visibility_timeout):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = False

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    payload = ''

    url_postfix = [name, "?receipt_handle={}&visibility_timeout={}".format(receipt_handle, visibility_timeout)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='queues')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_put, base_urls, url_postfix, data=json.dumps(payload), auth=auth, headers=headers, verify=verify)

    return (ret)


def create_lease(userId, lease_id):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = ['?lease_id={}'.format(lease_id)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_post, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def list_leases(userId):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = []
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def describe_lease(userId, lease_id):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [lease_id]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def acquire_lease(userId, lease_id, client_id, ttl):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [lease_id, 'acquire', '?client_id={}&ttl={}'.format(client_id, ttl)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def release_lease(userId, lease_id, client_id, epoch):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [lease_id, 'release', '?client_id={}&epoch={}'.format(client_id, epoch)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_get, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def refresh_lease(userId, lease_id, client_id, epoch, ttl):
    global localconfig, headers
    if localconfig == None:
        localconfig = anchore_engine.configuration.localconfig.get_config()

    ret = []

    if type(userId) == tuple:
        userId, pw = userId
    else:
        pw = ""
    auth = (userId, pw)

    url_postfix = [lease_id, 'ttl', '?client_id={}&ttl={}&epoch={}'.format(client_id, ttl, epoch)]
    base_urls = anchore_engine.clients.common.get_service_endpoints(auth, 'simplequeue', api_post='leases')
    verify = localconfig['internal_ssl_verify']

    ret = http.anchy_aa(http.anchy_put, base_urls, url_postfix, auth=auth, headers=headers, verify=verify)

    return (ret)


def get_threadbased_id(guarantee_uniq=False):
    """
    Returns a string for use with acquire() calls optionally. Constructs a consistent id from the platform node, process_id and thread_id

    :param guarantee_uniq: bool to have the id generate a uuid suffix to guarantee uniqeness between invocations even in the same thread
    :return: string
    """

    return '{}:{}:{}:{}'.format(platform.node(), os.getpid(), str(thread.get_ident()), uuid.uuid4().hex if guarantee_uniq else '')


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

    qobj = dequeue(user_auth, queue, max_wait_seconds=max_wait_seconds, visibility_timeout=visibility_timeout)
    receipt_handle = qobj.get('receipt_handle')
    msg_id = qobj.get('id')
    logger.debug('Got msg: {}'.format(qobj))
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
                                resp = update_message_visibility_timeout(userId=user_auth, name=queue, receipt_handle=receipt_handle, visibility_timeout=visibility_timeout)
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
        delete_message(user_auth, queue, receipt_handle)
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

    # Ensure task lease exists for acquisition and create if not found
    lease_resp = describe_lease(user_auth, lease_id)
    if not lease_resp:
        lease_resp = create_lease(user_auth, lease_id)

    if not lease_resp:
        raise Exception('Cannot locate or create a lease with id {}'.format(lease_id))

    # Acquire the task lease and run the task
    lease = None
    try:
        my_id = get_threadbased_id() if client_id is None else client_id
        lease = acquire_lease(user_auth, lease_id, client_id=my_id, ttl=ttl)

        if not lease:
            logger.warn('No lease returned from service, cannot proceed with task execution. Will retry on next cycle. Lease_id: {}'.format(lease_id))
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
                                resp = refresh_lease(user_auth, lease_id=lease['id'], client_id=lease['held_by'], epoch=lease['epoch'], ttl=ttl)
                                logger.debug('Lease {} refreshed with response: {}'.format(lease_id, resp))
                                if resp:
                                    lease = resp
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
    finally:
        try:
            if lease:
                resp = release_lease(user_auth, lease_id=lease['id'], client_id=lease['held_by'], epoch=lease['epoch'])
                logger.debug('Lease {} released with response: {}'.format(lease_id, resp))
            else:
                logger.warn('No lease found to release.')
        except Exception as e:
            logger.exception('Error releasing lease. Lease will expire on its own. Err: {}'.format(str(e)))
