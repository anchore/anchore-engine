import connexion
import time

from anchore_engine import db
import anchore_engine.services.catalog.catalog_impl
import anchore_engine.services.common
from anchore_engine.subsys import logger
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus

def status():
    httpcode = 500
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = anchore_engine.subsys.servicestatus.get_status({'hostid': localconfig['host_id'], 'servicename': 'catalog'})
        #return_object = {
        #    'busy': False,
        #    'up': True,
        #    'message': 'all good'
        #}        
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return (return_object, httpcode)

def repo_post(regrepo=None, autosubscribe=False, bodycontent={}):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'regrepo': regrepo, 'autosubscribe': autosubscribe})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.repo(session, request_inputs, bodycontent=bodycontent)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

def image_tags_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_tags(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)    

def image_get(tag=None, digest=None, imageId=None, registry_lookup=False, history=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request,
                                                                        default_params={'tag': tag, 'digest': digest, 'imageId': imageId, 'registry_lookup': registry_lookup, 'history': history})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def image_post(bodycontent={}, tag=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'tag': tag})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route('/image/<imageDigest>', methods=['GET', 'PUT', 'DELETE'])
def image_imageDigest_get(imageDigest):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def image_imageDigest_put(imageDigest, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def image_imageDigest_delete(imageDigest, force=False):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'force':False})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route('/registry_lookup', methods=['GET'])
def registry_lookup(tag=None, digest=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'tag': tag, 'digest': digest})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.registry_lookup(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route('/import', methods=['POST'])
def image_import(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_import(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# policy calls
# @api.route('/policies', methods=['GET', 'POST', 'PUT', 'DELETE'])
def policies_get(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.policies(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def policies_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.policies(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def policies_put(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.policies(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def policies_delete(bodycontent, cleanup_evals=True):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'cleanup_evals': cleanup_evals})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.policies(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# policy calls
# @api.route('/evals', methods=['GET', 'POST', 'PUT', 'DELETE'])
def evals_get(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.evals(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def evals_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.evals(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def evals_put(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.evals(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def evals_delete(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.evals(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# subscription calls
# @api.route('/subscriptions', methods=['GET', 'POST'])
def subscriptions_get(subscription_key=None, subscription_type=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'subscription_key':subscription_key, 'subscription_type':subscription_type})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def subscriptions_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route('/subscriptions/<subscriptionId>', methods=['GET', 'PUT', 'DELETE'])
def subscriptions_subscriptionId_get(subscriptionId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def subscriptions_subscriptionId_put(subscriptionId, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def subscriptions_subscriptionId_delete(subscriptionId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# eventlog calls
# @api.route('/events', methods=['GET', 'POST', 'DELETE'])
def events_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def events_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def events_delete():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# user calls
# @api.route("/users", methods=['GET'])
def users_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/users/<inuserId>", methods=['GET', 'DELETE'])
def users_userId_get(inuserId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users_userId(session, request_inputs, inuserId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def users_userId_delete(inuserId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users_userId(session, request_inputs, inuserId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# archive calls
# @api.route('/archive/<bucket>/<archiveid>', methods=['GET', 'POST'])
def archive_get(bucket, archiveid):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.archive(session, request_inputs, bucket, archiveid)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def archive_post(bucket, archiveid, bodycontent):
    try:
        # jsonbodycontent = json.loads(bodycontent)
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            # TODO HERE - some inputs are arrays of objects.....
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.archive(session, request_inputs, bucket, archiveid, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# system/service calls
# @api.route("/system", methods=['GET'])
def system_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/services", methods=['GET'])
def system_services_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/services/<servicename>", methods=['GET'])
def system_services_servicename_get(servicename):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename(session, request_inputs, servicename)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/services/<servicename>/<hostId>", methods=['GET', 'DELETE'])
def system_services_servicename_hostId_get(servicename, hostId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename_hostId(session, request_inputs, servicename, hostId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def system_services_servicename_hostId_delete(servicename, hostId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename_hostId(session, request_inputs, servicename, hostId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/registries", methods=['GET', 'POST'])
def system_registries_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def system_registries_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/registries/<registry>", methods=['GET', 'DELETE', 'PUT'])
def system_registries_registry_get(registry):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def system_registries_registry_delete(registry):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def system_registries_registry_put(registry, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/subscriptions", methods=['GET'])
def system_subscriptions_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_subscriptions(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

def system_prune_get():
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_prune_listresources(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

def system_prune_resourcetype_get(resourcetype, dangling=True, olderthan=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'dangling': dangling, 'olderthan': olderthan})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_prune(session, request_inputs, resourcetype)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

def system_prune_resourcetype_post(resourcetype, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_prune(session, request_inputs, resourcetype, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)
