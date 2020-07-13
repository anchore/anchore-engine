import connexion

import anchore_engine.apis
from anchore_engine import db
import anchore_engine.services.catalog.catalog_impl
import anchore_engine.common
from anchore_engine.subsys import logger
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED
from anchore_engine.db import AccountTypes
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.services.catalog import archiver
from anchore_engine.subsys.metrics import flask_metrics

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def status():
    httpcode = 500
    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def repo_post(regrepo=None, autosubscribe=False, lookuptag=None, dryrun=False, bodycontent={}):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'regrepo': regrepo, 'autosubscribe': autosubscribe, 'lookuptag': lookuptag, 'dryrun': dryrun})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.repo(session, request_inputs, bodycontent=bodycontent)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def image_tags_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_tags(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_images(tag=None, digest=None, imageId=None, registry_lookup=False, history=False):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request,
                                                             default_params={'tag': tag, 'digest': digest, 'imageId': imageId, 'registry_lookup': registry_lookup, 'history': history})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def add_image(image_metadata=None, tag=None, digest=None, created_at=None, from_archive=False, allow_dockerfile_update=False):
    try:
        if image_metadata is None:
            image_metadata = {}

        request_inputs = anchore_engine.apis.do_request_prep(connexion.request,
                                                             default_params={'tag': tag, 'digest': digest,
                                                                             'created_at': created_at, 'allow_dockerfile_update': allow_dockerfile_update})
        if from_archive:
            task = archiver.RestoreArchivedImageTask(account=ApiRequestContextProxy.namespace(), image_digest=digest)
            task.start()

            request_inputs['params'] = {}
            request_inputs['method'] = 'GET'

            with db.session_scope() as session:
                return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, digest)
        else:

            with db.session_scope() as session:
                return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image(session, request_inputs, bodycontent=image_metadata)

    except Exception as err:
        logger.exception('Error processing image add')
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route('/image/<imageDigest>', methods=['GET', 'PUT', 'DELETE'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_image(imageDigest):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_image(imageDigest, image):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest, bodycontent=image)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_image(imageDigest, force=False):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'force': False})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_imageDigest(session, request_inputs, imageDigest)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_images_async(imageDigests, force=False):
    try:
        account_id = ApiRequestContextProxy.namespace()
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.delete_images_async(account_id, session, imageDigests, force)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route('/registry_lookup', methods=['GET'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def registry_lookup(tag=None, digest=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'tag': tag, 'digest': digest})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.registry_lookup(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route('/import', methods=['POST'])
#@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
#def image_import(bodycontent):
#    try:
#        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
#        with db.session_scope() as session:
#            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.image_import(session, request_inputs, bodycontent=bodycontent)
#
#    except Exception as err:
#        httpcode = 500
#        return_object = str(err)
#
#    return return_object, httpcode



# policy calls



# subscription calls
# @api.route('/subscriptions', methods=['GET', 'POST'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def subscriptions_get(subscription_key=None, subscription_type=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'subscription_key':subscription_key, 'subscription_type':subscription_type})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def subscriptions_post(bodycontent):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route('/subscriptions/<subscriptionId>', methods=['GET', 'PUT', 'DELETE'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def subscriptions_subscriptionId_get(subscriptionId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def subscriptions_subscriptionId_put(subscriptionId, bodycontent):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def subscriptions_subscriptionId_delete(subscriptionId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.subscriptions(session, request_inputs, subscriptionId=subscriptionId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def events_get(source_servicename=None, source_hostid=None, resource_type=None, event_type=None, resource_id=None, level=None, since=None, before=None, page=None, limit=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request,
                                                             default_params={'source_servicename': source_servicename,
                                                                                        'source_hostid': source_hostid,
                                                                                        'resource_type': resource_type,
                                                                                        'resource_id': resource_id,
                                                                                        'event_type': event_type,
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

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def events_post(bodycontent):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def events_delete(since=None, before=None, level=None):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'since': since, 'before': before, 'level': level})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def events_eventId_get(eventId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events_eventId(session, request_inputs, eventId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def events_eventId_delete(eventId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.events_eventId(session, request_inputs, eventId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

# user calls
# @api.route("/users", methods=['GET'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def users_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/users/<inuserId>", methods=['GET', 'DELETE'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def users_userId_get(inuserId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users_userId(session, request_inputs, inuserId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def users_userId_delete(inuserId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.users_userId(session, request_inputs, inuserId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

# system/service calls
# @api.route("/system", methods=['GET'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/services", methods=['GET'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_services_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/services/<servicename>", methods=['GET'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_services_servicename_get(servicename):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename(session, request_inputs, servicename)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/services/<servicename>/<hostId>", methods=['GET', 'DELETE'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_services_servicename_hostId_get(servicename, hostId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename_hostId(session, request_inputs, servicename, hostId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_services_servicename_hostId_delete(servicename, hostId):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_services_servicename_hostId(session, request_inputs, servicename, hostId)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/registries", methods=['GET', 'POST'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_registries_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries(session, request_inputs)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_registries_post(bodycontent, validate=True):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'validate':validate})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries(session, request_inputs, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/registries/<registry>", methods=['GET', 'DELETE', 'PUT'])
@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_registries_registry_get(registry):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_registries_registry_delete(registry):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_registries_registry_put(registry, bodycontent, validate=True):
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'validate':validate})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_registries_registry(session, request_inputs, registry, bodycontent=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


# @api.route("/system/subscriptions", methods=['GET'])
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def system_subscriptions_get():
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        with db.session_scope() as session:
            return_object, httpcode = anchore_engine.services.catalog.catalog_impl.system_subscriptions(session, request_inputs)

    except Exception as err:
        logger.exception('Error fetching subscriptions')
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode

