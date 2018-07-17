import connexion
import time

from anchore_engine import db
import anchore_engine.services.catalog.catalog_impl
import anchore_engine.services.common
from anchore_engine.subsys import logger
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus

from anchore_engine.subsys.metrics import flask_metrics, flask_metric_name, enabled as flask_metrics_enabled

def status():
    httpcode = 500
    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return (return_object, httpcode)

def query_vulnerabilities_get(id=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'id': id})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.query_vulnerabilities(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)    

def query_images_by_package_get(pkg_name=None, pkg_version=None, pkg_type=None, distro=None, distro_version=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'pkg_name': pkg_name, 'pkg_version': pkg_version, 'pkg_type': pkg_type, 'distro': distro, 'distro_version': distro_version})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.query_images_by_package(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)    

def query_images_by_vulnerability_get(id=None, severity=None, vendor_only=True):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'id': id, 'severity': severity, 'vendor_only': vendor_only})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.query_images_by_vulnerability(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

def repo_post(regrepo=None, autosubscribe=False, lookuptag=None, bodycontent={}):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'regrepo': regrepo, 'autosubscribe': autosubscribe, 'lookuptag': lookuptag})
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


def image_post(bodycontent={}, tag=None, digest=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'tag': tag, 'digest': digest})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route('/image/<imageDigest>', methods=['GET', 'PUT', 'DELETE'])
@flask_metrics.do_not_track()
def image_imageDigest_get(imageDigest):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def image_imageDigest_put(imageDigest, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
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
@flask_metrics.do_not_track()
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
@flask_metrics.do_not_track()
def subscriptions_subscriptionId_get(subscriptionId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def subscriptions_subscriptionId_put(subscriptionId, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def subscriptions_subscriptionId_delete(subscriptionId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@flask_metrics.do_not_track()
def events_get(source_servicename=None, source_hostid=None, resource_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request,
                                                                        default_params={'source_servicename': source_servicename,
                                                                                        'source_hostid': source_hostid,
                                                                                        'resource_type': resource_type,
                                                                                        'resource_id': resource_id,
                                                                                        'level': level,
                                                                                        'since': since,
                                                                                        'before': before,
                                                                                        'page': page,
                                                                                        'limit': limit})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@flask_metrics.do_not_track()
def events_post(bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@flask_metrics.do_not_track()
def events_delete(since=None, before=None, level=None):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'since': since, 'before': before, 'level': level})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@flask_metrics.do_not_track()
def events_eventId_get(eventId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events_eventId(session, request_inputs, eventId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@flask_metrics.do_not_track()
def events_eventId_delete(eventId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events_eventId(session, request_inputs, eventId)

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
@flask_metrics.do_not_track()
def users_userId_get(inuserId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users_userId(session, request_inputs, inuserId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
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
@flask_metrics.do_not_track()
def archive_get(bucket, archiveid):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.archive(session, request_inputs, bucket, archiveid)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def archive_post(bucket, archiveid, bodycontent):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
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
@flask_metrics.do_not_track()
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
@flask_metrics.do_not_track()
def system_services_servicename_hostId_get(servicename, hostId):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename_hostId(session, request_inputs, servicename, hostId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
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


def system_registries_post(bodycontent, validate=True):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'validate':validate})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


# @api.route("/system/registries/<registry>", methods=['GET', 'DELETE', 'PUT'])
@flask_metrics.do_not_track()
def system_registries_registry_get(registry):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def system_registries_registry_delete(registry):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)

@flask_metrics.do_not_track()
def system_registries_registry_put(registry, bodycontent, validate=True):
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={'validate':validate})
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
