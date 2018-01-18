import connexion

from anchore_engine.services import common
from anchore_engine.subsys import simplequeue
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus

def status():
    request_inputs = common.do_request_prep(connexion.request, default_params={})

    localconfig = anchore_engine.configuration.localconfig.get_config()
    return_object = anchore_engine.subsys.servicestatus.get_status({'hostid': localconfig['host_id'], 'servicename': 'simplequeue'})
    #return_object = {
    #    'busy':False,
    #    'up':True,
    #    'message': 'all good'
    #}
    try:
        queue_detail = {}
        try:
            queuenames = simplequeue.get_queuenames()
            for queuename in queuenames:
                queue_detail[queuename] = {}
                qlen = simplequeue.qlen(queuename)
                queue_detail[queuename]['qlen'] = qlen
        except:
            pass
        return_object['detail'] = queue_detail
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)

def is_inqueue(queuename, bodycontent):
    request_inputs = common.do_request_prep(connexion.request, default_params={})
    try:
        return_object = simplequeue.is_inqueue(queuename, bodycontent)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)

def qlen(queuename):
    request_inputs = common.do_request_prep(connexion.request, default_params={})
    try:
        qlen = simplequeue.qlen(queuename)
        return_object = str(qlen)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)

def enqueue(queuename, bodycontent, forcefirst = None, qcount = 0):
    request_inputs = common.do_request_prep(connexion.request, default_params={'forcefirst':forcefirst, 'qcount':qcount})
    try:
        return_object = simplequeue.enqueue(queuename, bodycontent, qcount=qcount, forcefirst=forcefirst)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)


def dequeue(queuename):
    request_inputs = common.do_request_prep(connexion.request, default_params={})
    try:
        return_object = simplequeue.dequeue(queuename)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)

def queues():
    request_inputs = common.do_request_prep(connexion.request, default_params={})

    try:
        return_object = simplequeue.get_queuenames()
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)

