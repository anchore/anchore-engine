import copy
import datetime
import json
import os
import threading
import time

import pkg_resources
from sqlalchemy.exc import IntegrityError

import anchore_engine.clients.services.common
import anchore_engine.common

# anchore modules
import anchore_engine.common.helpers
import anchore_engine.common.images
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.events as events
import anchore_engine.subsys.metrics
import anchore_engine.subsys.servicestatus
from anchore_engine import db
from anchore_engine.clients import docker_registry
from anchore_engine.clients.services import internal_client_for, simplequeue
from anchore_engine.clients.services.simplequeue import SimpleQueueClient
from anchore_engine.common.helpers import make_policy_record
from anchore_engine.db import (
    AccountStates,
    AccountTypes,
    db_anchore,
    db_catalog_image,
    db_policybundle,
    db_queues,
    db_registries,
    db_services,
    db_subscriptions,
)
from anchore_engine.db.entities.catalog import ImageImportOperation, ImportState
from anchore_engine.service import ApiService, LifeCycleStages
from anchore_engine.services.catalog import archiver, catalog_impl
from anchore_engine.services.catalog.exceptions import (
    TagManifestNotFoundError,
    TagManifestParseError,
)
from anchore_engine.services.catalog.image_content.get_image_content import (
    ImageContentGetter,
    ImageDockerfileContentGetter,
    ImageManifestContentGetter,
)
from anchore_engine.subsys import (
    archive,
    logger,
    notifications,
    object_store,
    taskstate,
)
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.subsys.object_store.config import (
    ALT_OBJECT_STORE_CONFIG_KEY,
    DEFAULT_OBJECT_STORE_MANAGER_ID,
)
from anchore_engine.utils import AnchoreException, bytes_to_mb

##########################################################

# monitor section


def do_account_resources_delete(account_name: str):
    """
    Delete resources associated with the given account name

    :param account_name:
    :return:
    """

    return_object = {}
    httpcode = 500

    resourcemaps = [
        (
            "subscriptions",
            db.db_subscriptions.get_all_byuserId,
            catalog_impl.do_subscription_delete,
        ),
        ("registries", db.db_registries.get_byuserId, catalog_impl.do_registry_delete),
        (
            "evaluations",
            db.db_policyeval.get_all_byuserId,
            catalog_impl.do_evaluation_delete,
        ),
        (
            "policybundles",
            db.db_policybundle.get_all_byuserId,
            catalog_impl.do_policy_delete,
        ),
        ("images", db.db_catalog_image.get_all_byuserId, catalog_impl.do_image_delete),
        (
            "archive",
            db.db_archivemetadata.list_all_byuserId,
            catalog_impl.do_archive_delete,
        ),
        ("imports", list_account_import_ops, delete_image_import_resource),
    ]

    limit = 2048
    all_total = 0
    all_deleted = 0
    for resourcename, getfunc, delfunc in resourcemaps:
        try:
            deleted = 0
            total = 0
            with db.session_scope() as dbsession:
                records = getfunc(account_name, session=dbsession, limit=limit)
                total = len(records)
                return_object["total_{}".format(resourcename)] = total

                for record in records:
                    delfunc(account_name, record, dbsession, force=True)
                    deleted = deleted + 1

            return_object["total_{}_deleted".format(resourcename)] = deleted
            all_total = all_total + total
            all_deleted = all_deleted + deleted
            if total or deleted:
                logger.debug(
                    "deleted {} / {} {} records for account {}".format(
                        deleted, total, resourcename, account_name
                    )
                )

        except Exception as err:
            logger.warn(
                "failed to delete resources in {} for account {}, will continue and try again - exception: {}".format(
                    resourcename, account_name, err
                )
            )

    return_object["all_total"] = all_total
    return_object["all_deleted"] = all_deleted

    httpcode = 200
    return return_object, httpcode


def handle_account_resource_cleanup(*args, **kwargs):
    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    try:
        # iterate over all deleted account records, and perform resource cleanup for that account.  If there are no longer any resources associated with the account id, then finally delete the account record itself
        with db.session_scope() as dbsession:
            mgr = manager_factory.for_session(dbsession)
            accounts = mgr.list_accounts(
                with_state=AccountStates.deleting, include_service=False
            )

        for account in accounts:
            account_name = account["name"]

            logger.debug(
                "Inspecting account {} for resource cleanup tasks".format(account_name)
            )
            try:
                return_object, httpcode = do_account_resources_delete(account_name)
                logger.debug(
                    "Resources for deleted account cleaned-up: {} - {}".format(
                        return_object, httpcode
                    )
                )
                if (
                    return_object.get("all_total", None) == 0
                    and return_object.get("all_deleted", None) == 0
                ):
                    logger.debug(
                        "Resources for pending deleted account {} cleared - deleting account".format(
                            account_name
                        )
                    )
                    with db.session_scope() as session:
                        mgr = manager_factory.for_session(session)
                        mgr.delete_account(account_name)

                else:
                    logger.debug(
                        "resources for pending deleted account {} not entirely cleared this cycle".format(
                            account_name
                        )
                    )
            except Exception as err:
                raise Exception(
                    "failed to delete account {} resources - exception: {}".format(
                        account_name, err
                    )
                )

    except Exception as err:
        logger.warn("failure in handler - exception: " + str(err))

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def handle_vulnerability_scan(*args, **kwargs):
    global feed_sync_updated

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    try:
        all_ready = anchore_engine.clients.services.common.check_services_ready(
            ["policy_engine"]
        )
        if not all_ready:
            logger.debug(
                "FIRING DONE: feed syncer (skipping due to required services not being available)"
            )
            try:
                kwargs["mythread"]["last_return"] = False
            except:
                pass
            return True

        with db.session_scope() as dbsession:
            mgr = manager_factory.for_session(dbsession)
            accounts = mgr.list_accounts(
                with_state=AccountStates.enabled, include_service=False
            )

        for account in accounts:
            userId = account["name"]

            # vulnerability scans

            doperform = False
            vuln_subs = []
            for subscription_type in ["vuln_update"]:
                dbfilter = {"subscription_type": subscription_type}
                with db.session_scope() as dbsession:
                    subscription_records = db_subscriptions.get_byfilter(
                        userId, session=dbsession, **dbfilter
                    )
                for subscription_record in subscription_records:
                    if subscription_record["active"]:
                        image_info = anchore_engine.common.images.get_image_info(
                            userId,
                            "docker",
                            subscription_record["subscription_key"],
                            registry_lookup=False,
                            registry_creds=(None, None),
                        )
                        dbfilter = {
                            "registry": image_info["registry"],
                            "repo": image_info["repo"],
                            "tag": image_info["tag"],
                        }
                        if (
                            dbfilter,
                            subscription_record["subscription_value"],
                        ) not in vuln_subs:
                            vuln_subs.append(
                                (dbfilter, subscription_record["subscription_value"])
                            )

            for (dbfilter, value) in vuln_subs:
                with db.session_scope() as dbsession:
                    image_records = db_catalog_image.get_byimagefilter(
                        userId,
                        "docker",
                        dbfilter=dbfilter,
                        onlylatest=False,
                        session=dbsession,
                    )
                if value:
                    try:
                        subscription_value = json.loads(value)
                        digests = set(subscription_value["digests"])
                    except Exception:
                        digests = set()
                else:
                    digests = set()

                # always add latest version of the image
                if len(image_records) > 0:
                    digests.add(image_records[0]["imageDigest"])
                    current_imageDigest = image_records[0]["imageDigest"]

                for image_record in image_records:
                    if image_record["analysis_status"] == taskstate.complete_state(
                        "analyze"
                    ) and image_record["image_status"] == taskstate.base_state(
                        "image_status"
                    ):
                        imageDigest = image_record["imageDigest"]

                        if imageDigest not in digests:
                            continue

                        fulltag = (
                            dbfilter["registry"]
                            + "/"
                            + dbfilter["repo"]
                            + ":"
                            + dbfilter["tag"]
                        )

                        doperform = True
                        if doperform:
                            logger.debug(
                                "calling vuln scan perform: "
                                + str(fulltag)
                                + " : "
                                + str(imageDigest)
                            )
                            with db.session_scope() as dbsession:
                                try:
                                    catalog_impl.perform_vulnerability_scan(
                                        userId,
                                        imageDigest,
                                        dbsession,
                                        scantag=fulltag,
                                        force_refresh=False,
                                        is_current=(imageDigest == current_imageDigest),
                                    )
                                except Exception as err:
                                    logger.warn(
                                        "vulnerability scan failed - exception: "
                                        + str(err)
                                    )

    except Exception as err:
        logger.warn("failure in feed sync handler - exception: " + str(err))

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def generate_error_service_description(error_short_description: str) -> str:
    service_status = {
        "up": False,
        "available": False,
        "busy": False,
        "message": error_short_description,
        "detail": {},
        "version": "unknown",
        "db_version": "unknown",
    }
    return json.dumps(service_status)


def handle_service_watcher(*args, **kwargs):
    # global latest_service_records

    cycle_timer = kwargs["mythread"]["cycle_timer"]
    max_service_heartbeat_timer = 300
    max_service_orphaned_timer = 3600
    max_service_cleanup_timer = 86400

    while True:
        logger.debug("FIRING: service watcher")

        localconfig = anchore_engine.configuration.localconfig.get_config()

        with db.session_scope() as dbsession:
            event_account = anchore_engine.configuration.localconfig.ADMIN_ACCOUNT_NAME

            anchore_services = db_services.get_all(session=dbsession)
            # update the global latest service record dict in services.common
            # latest_service_records.update({"service_records": copy.deepcopy(anchore_services)})

            # fields to update each tick:
            #
            # heartbeat (current time)
            # status (true/false)
            # status_message (state of service)
            # short_description(api return)
            #

            for service in anchore_services:
                event = None
                service_update_record = {}
                if (
                    service["servicename"] == "catalog"
                    and service["hostid"] == localconfig["host_id"]
                ):
                    status = anchore_engine.subsys.servicestatus.get_status(service)
                    service_update_record.update(
                        {
                            "heartbeat": int(time.time()),
                            "status": True,
                            "status_message": taskstate.complete_state(
                                "service_status"
                            ),
                            "short_description": json.dumps(status),
                        }
                    )
                else:
                    try:
                        try:
                            status = json.loads(service["short_description"])
                        except:
                            status = json.loads(generate_error_service_description(""))

                        # set to down until the response can be parsed
                        service_update_record["status"] = False
                        service_update_record["status_message"] = taskstate.fault_state(
                            "service_status"
                        )
                        service_update_record[
                            "short_description"
                        ] = generate_error_service_description(
                            "could not get service status description"
                        )

                        try:
                            # NOTE: this is where any service-specific decisions based on the 'status' record could happen - now all services are the same
                            if status["up"] and status["available"]:
                                if (
                                    time.time() - service["heartbeat"]
                                    > max_service_heartbeat_timer
                                ):
                                    logger.warn(
                                        "no service heartbeat within allowed time period ({}) for service ({}/{}) - disabling service".format(
                                            max_service_heartbeat_timer,
                                            service["hostid"],
                                            service["servicename"],
                                        )
                                    )
                                    service_update_record[
                                        "short_description"
                                    ] = generate_error_service_description(
                                        "no heartbeat from service in ({}) seconds".format(
                                            max_service_heartbeat_timer
                                        )
                                    )

                                    # Trigger an event to log the down service
                                    event = events.ServiceDowned(
                                        user_id=event_account,
                                        name=service["servicename"],
                                        host=service["hostid"],
                                        url=service["base_url"],
                                        cause="no heartbeat from service in ({}) seconds".format(
                                            max_service_heartbeat_timer
                                        ),
                                    )
                                else:
                                    service_update_record["status"] = True
                                    service_update_record[
                                        "status_message"
                                    ] = taskstate.complete_state("service_status")
                                    service_update_record[
                                        "short_description"
                                    ] = json.dumps(status)
                            else:
                                # handle the down state transitions
                                if (
                                    time.time() - service["heartbeat"]
                                    > max_service_cleanup_timer
                                ):
                                    # remove the service entirely
                                    logger.warn(
                                        "no service heartbeat within allowed time period ({}) for service ({}/{}) - removing service".format(
                                            max_service_cleanup_timer,
                                            service["hostid"],
                                            service["servicename"],
                                        )
                                    )
                                    try:
                                        # remove the service record from DB
                                        removed_hostid = service["hostid"]
                                        removed_servicename = service["servicename"]
                                        removed_base_url = service["base_url"]

                                        db_services.delete(
                                            removed_hostid,
                                            removed_servicename,
                                            session=dbsession,
                                        )
                                        service_update_record = None

                                        # Trigger an event to log the orphaned service, only on transition
                                        event = events.ServiceRemoved(
                                            user_id=event_account,
                                            name=removed_servicename,
                                            host=removed_hostid,
                                            url=removed_base_url,
                                            cause="no heartbeat from service in ({}) seconds".format(
                                                max_service_cleanup_timer
                                            ),
                                        )
                                    except Exception as err:
                                        logger.warn(
                                            "attempt to remove service {}/{} failed - exception: {}".format(
                                                service.get("hostid"),
                                                service.get("servicename"),
                                                err,
                                            )
                                        )

                                elif (
                                    time.time() - service["heartbeat"]
                                    > max_service_orphaned_timer
                                ):
                                    # transition down service to orphaned
                                    logger.warn(
                                        "no service heartbeat within allowed time period ({}) for service ({}/{}) - orphaning service".format(
                                            max_service_orphaned_timer,
                                            service["hostid"],
                                            service["servicename"],
                                        )
                                    )
                                    service_update_record["status"] = False
                                    service_update_record[
                                        "status_message"
                                    ] = taskstate.orphaned_state("service_status")
                                    service_update_record[
                                        "short_description"
                                    ] = generate_error_service_description(
                                        "no heartbeat from service in ({}) seconds".format(
                                            max_service_orphaned_timer
                                        )
                                    )

                                    if service[
                                        "status_message"
                                    ] != taskstate.orphaned_state("service_status"):
                                        # Trigger an event to log the orphaned service, only on transition
                                        event = events.ServiceOrphaned(
                                            user_id=event_account,
                                            name=service["servicename"],
                                            host=service["hostid"],
                                            url=service["base_url"],
                                            cause="no heartbeat from service in ({}) seconds".format(
                                                max_service_orphaned_timer
                                            ),
                                        )

                        except Exception as err:
                            logger.warn(
                                "could not get/parse service status record for service: - exception: "
                                + str(err)
                            )

                    except Exception as err:
                        logger.warn(
                            "could not get service status: "
                            + str(service)
                            + " : exception: "
                            + str(err)
                            + " : "
                            + str(err.__dict__)
                        )
                        if service_update_record:
                            service_update_record["status"] = False
                            service_update_record[
                                "status_message"
                            ] = taskstate.fault_state("service_status")
                            service_update_record[
                                "short_description"
                            ] = generate_error_service_description(
                                "could not get service status"
                            )
                    finally:
                        if event:
                            catalog_impl.add_event(event, dbsession)

                if service_update_record:
                    service.update(service_update_record)
                    try:
                        db_services.update_record(service, session=dbsession)
                    except Exception as err:
                        logger.warn("could not update DB: " + str(err))

        logger.debug("FIRING DONE: service watcher")
        try:
            kwargs["mythread"]["last_return"] = True
        except:
            pass

        time.sleep(cycle_timer)
    return True


def handle_repo_watcher(*args, **kwargs):
    global system_user_auth

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        accounts = mgr.list_accounts(
            with_state=AccountStates.enabled, include_service=False
        )

    for account in accounts:
        userId = account["name"]

        dbfilter = {}
        with db.session_scope() as dbsession:
            dbfilter["subscription_type"] = "repo_update"
            subscription_records = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )

            registry_creds = db_registries.get_byuserId(userId, session=dbsession)
            try:
                catalog_impl.refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

        for subscription_record in subscription_records:
            if not subscription_record["active"]:
                continue

            event = None
            subscription_id = subscription_record["subscription_id"]

            try:
                regrepo = subscription_record["subscription_key"]
                if subscription_record["subscription_value"]:
                    subscription_value = json.loads(
                        subscription_record["subscription_value"]
                    )
                    if "autosubscribe" not in subscription_value:
                        subscription_value["autosubscribe"] = False
                    if "lookuptag" not in subscription_value:
                        subscription_value["lookuptag"] = "latest"

                else:
                    subscription_value = {"autosubscribe": False, "lookuptag": "latest"}

                stored_repotags = subscription_value.get("repotags", [])

                fulltag = regrepo + ":" + subscription_value.get("lookuptag", "latest")
                image_info = anchore_engine.common.images.get_image_info(
                    userId,
                    "docker",
                    fulltag,
                    registry_lookup=False,
                    registry_creds=(None, None),
                )
                # List tags
                try:
                    curr_repotags = docker_registry.get_repo_tags(
                        userId, image_info, registry_creds=registry_creds
                    )
                except AnchoreException as e:
                    event = events.ListTagsFailed(
                        user_id=userId,
                        registry=image_info.get("registry", None),
                        repository=image_info.get("repo", None),
                        error=e.to_dict(),
                    )
                    raise e

                autosubscribes = ["analysis_update"]
                if subscription_value["autosubscribe"]:
                    autosubscribes.append("tag_update")

                repotags = set(curr_repotags).difference(set(stored_repotags))
                if repotags:
                    logger.debug(
                        "new tags to watch in repo ("
                        + str(regrepo)
                        + "): "
                        + str(repotags)
                    )
                    added_repotags = stored_repotags

                    for repotag in repotags:
                        try:
                            fulltag = (
                                image_info["registry"]
                                + "/"
                                + image_info["repo"]
                                + ":"
                                + repotag
                            )
                            logger.debug("found new tag in repo: " + str(fulltag))
                            try:
                                new_image_info = (
                                    anchore_engine.common.images.get_image_info(
                                        userId,
                                        "docker",
                                        fulltag,
                                        registry_lookup=True,
                                        registry_creds=registry_creds,
                                    )
                                )
                            except Exception as err:
                                event = events.ImageRegistryLookupFailed(
                                    user_id=userId,
                                    image_pull_string=fulltag,
                                    data=err.__dict__,
                                )
                                raise err

                            manifest = None
                            try:
                                if "manifest" in new_image_info:
                                    try:
                                        manifest = json.dumps(
                                            new_image_info["manifest"]
                                        )
                                    except Exception as err:
                                        raise TagManifestParseError(
                                            cause=err,
                                            tag=fulltag,
                                            manifest=new_image_info["manifest"],
                                            msg="Failed to serialize manifest into JSON formatted string",
                                        )
                                else:
                                    raise TagManifestNotFoundError(
                                        tag=fulltag,
                                        msg="No manifest from get_image_info",
                                    )
                            except AnchoreException as e:
                                event = events.TagManifestParseFailed(
                                    user_id=userId, tag=fulltag, error=e.to_dict()
                                )
                                raise

                            if not catalog_impl.is_image_valid_size(new_image_info):
                                localconfig = (
                                    anchore_engine.configuration.localconfig.get_config()
                                )
                                raise Exception(
                                    "Image size of "
                                    + str(
                                        bytes_to_mb(
                                            new_image_info["compressed_size"],
                                            round_to=2,
                                        )
                                    )
                                    + " MB exceeds configured maximum of "
                                    + str(
                                        localconfig.get("max_compressed_image_size_mb")
                                    )
                                    + " MB"
                                )

                            with db.session_scope() as dbsession:
                                # One last check for repo subscription status before adding image
                                if not db_subscriptions.is_active(
                                    userId, subscription_id, dbsession
                                ):
                                    logger.debug(
                                        "Aborting repo scan for %s for account %s, subscription is no longer active"
                                        % (regrepo, userId)
                                    )
                                    break

                                logger.debug(
                                    "adding/updating image from repo scan "
                                    + str(new_image_info["fulltag"])
                                )

                                # add the image
                                catalog_impl.add_or_update_image(
                                    dbsession,
                                    userId,
                                    new_image_info["imageId"],
                                    tags=[new_image_info["fulltag"]],
                                    digests=[new_image_info["fulldigest"]],
                                    parentdigest=new_image_info.get(
                                        "parentdigest", None
                                    ),
                                    manifest=manifest,
                                )
                                # add the subscription records with the configured default activations

                                for (
                                    stype
                                ) in anchore_engine.common.tag_subscription_types:
                                    activate = False
                                    if stype in autosubscribes:
                                        activate = True
                                    db_subscriptions.add(
                                        userId,
                                        new_image_info["fulltag"],
                                        stype,
                                        {"active": activate},
                                        session=dbsession,
                                    )

                            added_repotags.append(repotag)
                        except Exception as err:
                            logger.warn(
                                "could not add discovered tag from repo ("
                                + str(fulltag)
                                + ") - exception: "
                                + str(err)
                            )

                    # update the subscription record with the latest successfully added image tags
                    with db.session_scope() as dbsession:
                        subscription_value["repotags"] = added_repotags
                        subscription_value["tagcount"] = len(added_repotags)
                        db_subscriptions.update_subscription_value(
                            account=userId,
                            subscription_id=subscription_id,
                            subscription_value=json.dumps(subscription_value),
                            session=dbsession,
                        )

                else:
                    logger.debug(
                        "no new images in watched repo (" + str(regrepo) + "): skipping"
                    )
            except Exception as err:
                logger.warn(
                    "failed to process repo_update subscription - exception: "
                    + str(err)
                )
            finally:
                if event:
                    with db.session_scope() as dbsession:
                        catalog_impl.add_event(event, dbsession)

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def handle_image_watcher(*args, **kwargs):
    global system_user_auth

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    obj_mgr = object_store.get_manager()

    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        accounts = mgr.list_accounts(
            with_state=AccountStates.enabled, include_service=False
        )

    for account in accounts:
        userId = account["name"]
        if account["type"] == AccountTypes.service:  # userId == 'anchore-system':
            continue

        with db.session_scope() as dbsession:
            dbfilter = {}
            dbfilter["subscription_type"] = "tag_update"
            subscription_records = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )

            registry_creds = db_registries.get_byuserId(userId, session=dbsession)
            try:
                catalog_impl.refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

        alltags = []
        for subscription_record in subscription_records:
            if not subscription_record["active"]:
                continue

            try:
                fulltag = subscription_record["subscription_key"]
                if fulltag not in alltags:
                    alltags.append(fulltag)

            except Exception as err:
                logger.warn(
                    "problem creating taglist for image watcher - exception: "
                    + str(err)
                )

        for registry_record in registry_creds:
            try:
                docker_registry.ping_docker_registry(registry_record)
            except Exception as err:
                registry_record["record_state_key"] = "auth_failure"
                registry_record["record_state_val"] = str(int(time.time()))
                logger.warn("registry ping failed - exception: " + str(err))

        logger.debug("checking tags for update: " + str(userId) + " : " + str(alltags))
        for fulltag in alltags:
            event = None
            try:
                logger.debug("checking image latest info from registry: " + fulltag)

                try:
                    image_info = anchore_engine.common.images.get_image_info(
                        userId,
                        "docker",
                        fulltag,
                        registry_lookup=True,
                        registry_creds=registry_creds,
                    )
                except Exception as err:
                    event = events.ImageRegistryLookupFailed(
                        user_id=userId, image_pull_string=fulltag, data=err.__dict__
                    )
                    raise err
                logger.spew("checking image: got registry info: " + str(image_info))

                manifest = None
                try:
                    if "manifest" in image_info:
                        try:
                            manifest = json.dumps(image_info["manifest"])
                        except Exception as err:
                            raise TagManifestParseError(
                                cause=err,
                                tag=fulltag,
                                manifest=image_info["manifest"],
                                msg="Failed to serialize manifest into JSON formatted string",
                            )
                    else:
                        raise TagManifestNotFoundError(
                            tag=fulltag, msg="No manifest from get_image_info"
                        )
                except AnchoreException as e:
                    event = events.TagManifestParseFailed(
                        user_id=userId, tag=fulltag, error=e.to_dict()
                    )
                    raise

                if not catalog_impl.is_image_valid_size(image_info):
                    localconfig = anchore_engine.configuration.localconfig.get_config()
                    raise Exception(
                        "Image ("
                        + str(fulltag)
                        + ") size of "
                        + str(bytes_to_mb(image_info["compressed_size"], round_to=2))
                        + " MB exceeds configured maximum size of "
                        + str(localconfig.get("max_compressed_image_size_mb"))
                        + " MB"
                    )

                parent_manifest = json.dumps(image_info.get("parentmanifest", {}))

                try:
                    dbfilter = {
                        "registry": image_info["registry"],
                        "repo": image_info["repo"],
                        "tag": image_info["tag"],
                        "digest": image_info["digest"],
                    }
                except Exception as err:
                    raise Exception(
                        "could not prepare db filter for complete lookup check - exception: "
                        + str(err)
                    )

                try:
                    stored_manifest = json.loads(
                        obj_mgr.get_document(
                            userId, "manifest_data", image_info["digest"]
                        )
                    )
                    if not stored_manifest:
                        raise Exception("stored manifest is empty")
                except Exception as err:
                    logger.debug(
                        "found empty/invalid stored manifest, storing new: " + str(err)
                    )
                    obj_mgr.put_document(
                        userId, "manifest_data", image_info["digest"], manifest
                    )

                try:
                    stored_parent_manifest = json.loads(
                        obj_mgr.get_document(
                            userId, "parent_manifest_data", image_info["digest"]
                        )
                    )
                    if not stored_parent_manifest:
                        raise Exception("stored parent manifest is empty")
                except Exception as err:
                    logger.debug(
                        "found empty/invalid stored parent manifest, storing new: "
                        + str(err)
                    )
                    obj_mgr.put_document(
                        userId,
                        "parent_manifest_data",
                        image_info["digest"],
                        parent_manifest,
                    )

                logger.debug(
                    "checking image: looking up image in db using dbfilter: "
                    + str(dbfilter)
                )
                with db.session_scope() as dbsession:
                    record = db_catalog_image.get_byimagefilter(
                        userId, "docker", dbfilter, session=dbsession
                    )
                if record:
                    logger.debug(
                        "checking image: found match, no update, nothing to do: "
                        + str(fulltag)
                    )
                else:
                    logger.info(
                        "checking image: found latest digest for tag is not in DB: should update and queue for analysis: tag="
                        + str(fulltag)
                        + " latest_digest="
                        + str(dbfilter["digest"])
                    )
                    # get the set of existing digests
                    try:
                        last_dbfilter = {}
                        last_dbfilter.update(dbfilter)
                        last_dbfilter.pop("digest", None)

                        last_digests = []
                        last_annotations = {}
                        is_latest = True
                        with db.session_scope() as dbsession:
                            last_image_records = db_catalog_image.get_byimagefilter(
                                userId, "docker", last_dbfilter, session=dbsession
                            )

                        if last_image_records:
                            for last_image_record in last_image_records:
                                for image_detail in last_image_record["image_detail"]:
                                    last_digests.append(image_detail["digest"])

                                # only do this (bring forward annotations) for the first found digest (last digest associated with tag)
                                if is_latest:
                                    if (
                                        not last_annotations
                                        and last_image_record["annotations"]
                                    ):
                                        try:
                                            if last_image_record.get(
                                                "annotations", "{}"
                                            ):
                                                last_annotations.update(
                                                    json.loads(
                                                        last_image_record.get(
                                                            "annotations", "{}"
                                                        )
                                                    )
                                                )
                                        except:
                                            pass
                                    is_latest = False

                    except Exception as err:
                        logger.error(str(err))

                    # add and store the new image
                    with db.session_scope() as dbsession:
                        logger.debug(
                            "adding new image from tag watcher " + str(image_info)
                        )
                        image_records = catalog_impl.add_or_update_image(
                            dbsession,
                            userId,
                            image_info["imageId"],
                            tags=[image_info["fulltag"]],
                            digests=[image_info["fulldigest"]],
                            parentdigest=image_info.get("parentdigest", None),
                            manifest=manifest,
                            parent_manifest=parent_manifest,
                            annotations=last_annotations,
                        )

                    if image_records:
                        image_record = image_records[0]
                    else:
                        image_record = {}

                    logger.info("checking image: added new image: " + str(image_record))
                    new_digests = [image_info["digest"]]

                    # construct the notification and queue
                    try:
                        npayload = {
                            "last_eval": last_digests,
                            "curr_eval": new_digests,
                        }
                        if last_annotations:
                            npayload["annotations"] = last_annotations

                        notifications.queue_notification(
                            userId, fulltag, "tag_update", npayload
                        )
                        logger.debug("queued image tag update notification: " + fulltag)

                        # inobj = {
                        #    'userId': userId,
                        #    'subscription_key':fulltag,
                        #    'notificationId': str(uuid.uuid4()),
                        #    'last_eval':last_digests,
                        #    'curr_eval':new_digests,
                        # }
                        # if not simplequeue.is_inqueue(system_user_auth, 'tag_update', inobj):
                        #    qobj = simplequeue.enqueue(system_user_auth, 'tag_update', inobj)
                        #    logger.debug("queued image tag update notification: " + fulltag)

                    except Exception as err:
                        logger.error(
                            "failed to queue tag update notification - exception: "
                            + str(err)
                        )
                        raise err

            except Exception as err:
                logger.error("failed to check/update image - exception: " + str(err))
            finally:
                if event:
                    with db.session_scope() as dbsession:
                        catalog_impl.add_event(event, dbsession)

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def check_feedmeta_update(dbsession):
    global feed_sync_updated
    return feed_sync_updated


def check_policybundle_update(userId, dbsession):
    global bundle_user_last_updated

    is_updated = True

    try:
        last_bundle_update = 0
        active_policy_record = db_policybundle.get_active_policy(
            userId, session=dbsession
        )
        if active_policy_record:
            last_bundle_update = active_policy_record["last_updated"]
        else:
            logger.warn(
                "user has no active policy - queueing just in case" + str(userId)
            )
            return is_updated

        if userId not in bundle_user_last_updated:
            bundle_user_last_updated[userId] = last_bundle_update

        if last_bundle_update == bundle_user_last_updated[userId]:
            logger.debug("no bundle update detected since last cycle")
            is_updated = False
        else:
            logger.debug("bundle update detected since last cycle")
            bundle_user_last_updated[userId] = last_bundle_update
            is_updated = True
    except Exception as err:
        logger.warn(
            "failed to get/parse active policy bundle for user ("
            + str(userId)
            + ") - exception: "
            + str(err)
        )
        bundle_user_last_updated[userId] = 0
        is_updated = True

    return is_updated


def handle_policyeval(*args, **kwargs):
    global system_user_auth, bundle_user_is_updated, feed_sync_updated

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    try:
        all_ready = anchore_engine.clients.services.common.check_services_ready(
            ["policy_engine", "simplequeue"]
        )
        if not all_ready:
            logger.debug(
                "FIRING DONE: policy eval (skipping due to required services not being available)"
            )
            try:
                kwargs["mythread"]["last_return"] = False
            except:
                pass
            return True

        with db.session_scope() as dbsession:
            mgr = manager_factory.for_session(dbsession)
            accounts = mgr.list_accounts(
                with_state=AccountStates.enabled, include_service=False
            )

        for account in accounts:
            userId = account["name"]
            # policy evaluations

            doperform = False
            policy_subs = []
            for subscription_type in ["policy_eval"]:
                dbfilter = {"subscription_type": subscription_type}
                with db.session_scope() as dbsession:
                    subscription_records = db_subscriptions.get_byfilter(
                        userId, session=dbsession, **dbfilter
                    )
                for subscription_record in subscription_records:
                    if subscription_record["active"]:
                        image_info = anchore_engine.common.images.get_image_info(
                            userId,
                            "docker",
                            subscription_record["subscription_key"],
                            registry_lookup=False,
                            registry_creds=(None, None),
                        )
                        dbfilter = {
                            "registry": image_info["registry"],
                            "repo": image_info["repo"],
                            "tag": image_info["tag"],
                        }
                        if (
                            dbfilter,
                            subscription_record["subscription_value"],
                        ) not in policy_subs:
                            policy_subs.append(
                                (dbfilter, subscription_record["subscription_value"])
                            )

            for (dbfilter, value) in policy_subs:
                with db.session_scope() as dbsession:
                    image_records = db_catalog_image.get_byimagefilter(
                        userId,
                        "docker",
                        dbfilter=dbfilter,
                        onlylatest=False,
                        session=dbsession,
                    )
                if value:
                    try:
                        subscription_value = json.loads(value)
                        digests = set(subscription_value["digests"])
                    except Exception:
                        digests = set()
                else:
                    digests = set()

                # always add latest version of the image
                if len(image_records) > 0:
                    digests.add(image_records[0]["imageDigest"])
                for image_record in image_records:
                    if image_record["analysis_status"] == taskstate.complete_state(
                        "analyze"
                    ) and image_record["image_status"] == taskstate.base_state(
                        "image_status"
                    ):
                        imageDigest = image_record["imageDigest"]

                        if imageDigest not in digests:
                            continue

                        fulltag = (
                            dbfilter["registry"]
                            + "/"
                            + dbfilter["repo"]
                            + ":"
                            + dbfilter["tag"]
                        )

                        # TODO - checks to avoid performing eval if nothing has changed
                        doperform = True
                        if doperform:
                            logger.debug(
                                "calling policy eval perform: "
                                + str(fulltag)
                                + " : "
                                + str(imageDigest)
                            )
                            with db.session_scope() as dbsession:
                                try:
                                    catalog_impl.perform_policy_evaluation(
                                        userId, imageDigest, dbsession, evaltag=fulltag
                                    )
                                except Exception as err:
                                    logger.warn(
                                        "policy evaluation failed - exception: "
                                        + str(err)
                                    )

    except Exception as err:
        logger.warn(
            "failure in policy eval / vuln scan handler - exception: " + str(err)
        )

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def handle_analyzer_queue(*args, **kwargs):
    global system_user_auth

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    localconfig = anchore_engine.configuration.localconfig.get_config()

    obj_mgr = object_store.get_manager()

    max_working_time = 36000
    try:
        max_working_time = int(localconfig["image_analyze_timeout_seconds"])
    except:
        max_working_time = 36000

    fair_share_enabled = True
    try:
        if (
            str(
                localconfig.get("services", {})
                .get("catalog", {})
                .get("fair_share_image_analysis_queueing", "True")
            ).lower()
            == "false"
        ):
            fair_share_enabled = False
    except:
        fair_share_enabled = True

    all_ready = anchore_engine.clients.services.common.check_services_ready(
        ["policy_engine", "simplequeue"]
    )
    if not all_ready:
        logger.debug(
            "FIRING DONE: analyzer queuer (skipping due to required services not being available)"
        )
        try:
            kwargs["mythread"]["last_return"] = False
        except:
            pass
        return True

    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        accounts = mgr.list_accounts(include_service=False)

    q_client = internal_client_for(SimpleQueueClient, userId=None)
    queue_rebalance = {}
    highest_neg_queueId = -1 * (
        1024 * 1000
    )  # choose a high value in the negative space as a starting point - this needs to be a value that fits when stored as 'big integer' SQL type
    for account in accounts:
        userId = account["name"]
        if account["type"] == AccountTypes.service:
            continue

        if userId not in queue_rebalance:
            queue_rebalance[userId] = {}

        # do this in passes, for each analysis_status state
        with db.session_scope() as dbsession:
            dbfilter = {
                "analysis_status": taskstate.working_state("analyze"),
                "image_status": taskstate.base_state("image_status"),
            }
            workingstate_image_records = db_catalog_image.get_byfilter(
                userId, session=dbsession, **dbfilter
            )

        # first, evaluate images looking for those that have been in working state for too long and reset
        for image_record in workingstate_image_records:
            imageDigest = image_record["imageDigest"]
            if image_record["image_status"] == taskstate.complete_state("image_status"):
                state_time = int(time.time()) - image_record["last_updated"]
                logger.debug(
                    "image in working state for ("
                    + str(state_time)
                    + ")s - "
                    + str(imageDigest)
                )
                if state_time > max_working_time:
                    logger.warn(
                        "image has been in working state ("
                        + str(taskstate.working_state("analyze"))
                        + ") for over ("
                        + str(max_working_time)
                        + ") seconds - resetting and requeueing for analysis"
                    )
                    image_record["analysis_status"] = taskstate.reset_state("analyze")
                    with db.session_scope() as dbsession:
                        db_catalog_image.update_record(image_record, session=dbsession)

        # next, look for any image in base state (not_analyzed) for queuing
        with db.session_scope() as dbsession:
            dbfilter = {
                "analysis_status": taskstate.base_state("analyze"),
                "image_status": taskstate.base_state("image_status"),
            }
            basestate_image_records = db_catalog_image.get_byfilter(
                userId, session=dbsession, **dbfilter
            )

        for basestate_image_record in basestate_image_records:
            imageDigest = basestate_image_record["imageDigest"]

            image_record = basestate_image_record

            if image_record["image_status"] == taskstate.complete_state("image_status"):
                logger.debug(
                    "image check of queue status for digest {}".format(imageDigest)
                )
                if image_record["analysis_status"] == taskstate.base_state("analyze"):
                    logger.debug("image in base state - " + str(imageDigest))

                    # TODO: This is expensive once the queue gets longer... need to find a more efficient way to check status
                    # The right way is keep a msg/task ID in the db record so we can do a quick lookup in the queue for the id rather than full content match
                    try:
                        manifest = obj_mgr.get_document(
                            userId, "manifest_data", image_record["imageDigest"]
                        )
                    except Exception as err:
                        logger.debug("failed to get manifest - {}".format(str(err)))
                        manifest = {}

                    try:
                        parent_manifest = obj_mgr.get_document(
                            userId, "parent_manifest_data", image_record["imageDigest"]
                        )
                    except Exception:
                        parent_manifest = {}

                    qobj = {}
                    qobj["userId"] = userId
                    qobj["imageDigest"] = image_record["imageDigest"]
                    qobj["manifest"] = manifest
                    qobj["parent_manifest"] = parent_manifest

                    try:
                        q_record = q_client.is_inqueue("images_to_analyze", qobj)
                        if not q_record:
                            # queue image for analysis
                            priority = False
                            logger.debug(
                                "queued image for analysis (priority={}): {}".format(
                                    priority, str(imageDigest)
                                )
                            )
                            qobj = q_client.enqueue(
                                "images_to_analyze", qobj, forcefirst=priority
                            )

                        else:
                            logger.debug("image already queued")
                            # track and store the account's lowest queueId in the task queue, as well as the global highest negative space queueId across all accounts
                            try:
                                lowest_queueId = queue_rebalance[userId].get(
                                    "lowest_queueId", None
                                )
                                if (
                                    not lowest_queueId
                                    or q_record.get("queueId") < lowest_queueId
                                ):
                                    queue_rebalance[userId][
                                        "lowest_queueId"
                                    ] = q_record.get("queueId")
                                if (
                                    q_record.get("queueId") < 0
                                    and q_record.get("queueId") >= highest_neg_queueId
                                ):
                                    highest_neg_queueId = q_record.get("queueId")
                            except Exception as err:
                                logger.error(
                                    "failed to store image current queueID - excpetion: {}".format(
                                        err
                                    )
                                )

                    except Exception as err:
                        logger.error(
                            "failed to check/queue image for analysis - exception: "
                            + str(err)
                        )

    # promote queued tasks into the analysis queue such that one image from each account is prioritized, to implement a simple 'fair share' across accounts
    if fair_share_enabled:
        try:
            queue_id_updates = _perform_queue_rebalance(
                queue_rebalance, highest_neg_queueId
            )
            for src, dst in queue_id_updates:
                q_client.update_queueid(
                    "images_to_analyze", src_queueId=src, dst_queueId=dst
                )
        except:
            logger.exception("Ignoring errors rebalancing analysis queue")

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def _perform_queue_rebalance(queue_rebalance, highest_neg_queueId):
    ret = []
    for userId in queue_rebalance.keys():
        user_lowest_queueId = queue_rebalance[userId].get("lowest_queueId", None)
        if user_lowest_queueId and user_lowest_queueId > 0:
            # shuffle the task into neg space
            highest_neg_queueId += 1
            if highest_neg_queueId <= -1:
                logger.spew(
                    "prioritizing user {} image in image analysis queue for fair-share (queueId={}, new_queueId={})".format(
                        userId, user_lowest_queueId, highest_neg_queueId
                    )
                )
                ret.append((user_lowest_queueId, highest_neg_queueId))
    return ret


def handle_notifications(*args, **kwargs):
    global system_user_auth

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    q_client = internal_client_for(SimpleQueueClient, userId=None)

    with db.session_scope() as dbsession:
        mgr = manager_factory.for_session(dbsession)
        localconfig = anchore_engine.configuration.localconfig.get_config()

        try:
            notification_timeout = int(
                localconfig["webhooks"]["notification_retry_timeout"]
            )
        except:
            notification_timeout = 30

        logger.debug("notification timeout: " + str(notification_timeout))

        # get the event log notification config
        try:
            event_log_config = (
                localconfig.get("services", {})
                .get("catalog", {})
                .get("event_log", None)
            )
            if event_log_config and "notification" in event_log_config:
                notify_events = event_log_config.get("notification").get(
                    "enabled", False
                )
                if notify_events and "level" in event_log_config.get("notification"):
                    event_levels = event_log_config.get("notification").get("level")
                    event_levels = [level.lower() for level in event_levels]
                else:
                    event_levels = None
            else:
                notify_events = False
                event_levels = None
        except:
            logger.exception("Ignoring errors parsing for event_log configuration")
            notify_events = False
            event_levels = None

        # regular event queue notifications + event log notification
        event_log_type = "event_log"
        for subscription_type in anchore_engine.common.subscription_types + [
            event_log_type
        ]:
            logger.debug("notifier: " + subscription_type)
            accounts = mgr.list_accounts(
                with_state=AccountStates.enabled, include_service=False
            )

            try:
                qlen = q_client.qlen(subscription_type)
            except Exception as err:
                logger.debug(
                    "problem looking for notifications in queue: "
                    + str(subscription_type)
                    + " - exception: "
                    + str(err)
                )
                qlen = 0

            while qlen > 0:
                pupdate_record = q_client.dequeue(subscription_type)
                if pupdate_record:
                    logger.debug(
                        "got notification from queue: "
                        + json.dumps(pupdate_record, indent=4)
                    )
                    notification = pupdate_record["data"]
                    userId = notification["userId"]
                    subscription_key = notification["subscription_key"]
                    notificationId = notification["notificationId"]
                    for account in accounts:
                        try:
                            if userId == account["name"]:
                                notification_record = None

                                # new handling
                                subscription_type_actual = subscription_type

                                if (
                                    notification.get("event", {})
                                    .get("details", {})
                                    .get("subscription_type", None)
                                    in anchore_engine.common.subscription_types
                                ):
                                    subscription_type_actual = (
                                        notification.get("event", {})
                                        .get("details", {})
                                        .get("subscription_type")
                                    )
                                    subscription_key_actual = (
                                        notification.get("event", {})
                                        .get("resource", {})
                                        .get("id")
                                    )
                                    dbfilter = {
                                        "subscription_type": subscription_type_actual,
                                        "subscription_key": subscription_key_actual,
                                    }
                                    subscription_records = (
                                        db_subscriptions.get_byfilter(
                                            account["name"],
                                            session=dbsession,
                                            **dbfilter,
                                        )
                                    )
                                    if subscription_records:
                                        subscription = subscription_records[0]
                                        if subscription and subscription["active"]:
                                            notification_transform = {
                                                "notificationId": notification.get(
                                                    "notificationId"
                                                ),
                                                "userId": notification.get("userId"),
                                                "subscription_key": subscription_key_actual,
                                            }
                                            notification_transform.update(
                                                notification.get("event", {}).get(
                                                    "details", {}
                                                )
                                            )
                                            notification_record = (
                                                notifications.make_notification(
                                                    account,
                                                    subscription_type_actual,
                                                    notification_transform,
                                                )
                                            )

                                else:
                                    if notify_events and (
                                        event_levels is None
                                        or subscription_key.lower() in event_levels
                                    ):
                                        notification.pop(
                                            "subscription_key", None
                                        )  # remove subscription_key property from notification
                                        notification_record = (
                                            notifications.make_notification(
                                                account, subscription_type, notification
                                            )
                                        )
                                if notification_record:
                                    logger.spew(
                                        "Storing NOTIFICATION: {} - {} - {}".format(
                                            account,
                                            notification_record,
                                            subscription_type,
                                        )
                                    )
                                    db_queues.add(
                                        subscription_type_actual,
                                        userId,
                                        notificationId,
                                        notification_record,
                                        0,
                                        int(time.time() + notification_timeout),
                                        session=dbsession,
                                    )
                        except Exception as err:
                            import traceback

                            traceback.print_exc()
                            logger.warn(
                                "cannot store notification to DB - exception: "
                                + str(err)
                            )

                qlen = q_client.qlen(subscription_type)

            for account in accounts:
                notification_records = db_queues.get_all(
                    subscription_type, account["name"], session=dbsession
                )
                for notification_record in notification_records:
                    logger.spew("drained to send: " + json.dumps(notification_record))
                    try:
                        rc = notifications.notify(account, notification_record)
                        if rc:
                            db_queues.delete_record(
                                notification_record, session=dbsession
                            )
                    except Exception as err:
                        logger.debug(
                            "failed to send notification, storing for retry - exception: "
                            + str(err)
                        )
                        notification_record["tries"] = int(time.time())
                        if (
                            notification_record["tries"]
                            > notification_record["max_tries"]
                        ):
                            logger.error(
                                "hit max notification timeout: dropping notificaion"
                            )
                            db_queues.delete_record(
                                notification_record, session=dbsession
                            )
                        else:
                            db_queues.update_record(
                                notification_record, session=dbsession
                            )

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


def handle_metrics(*args, **kwargs):
    cycle_timer = kwargs["mythread"]["cycle_timer"]

    while True:

        # perform some DB read/writes for metrics gathering
        if anchore_engine.subsys.metrics.is_enabled():

            # DB probes
            anchore_record = None
            try:
                with anchore_engine.subsys.metrics.get_summary_obj(
                    "anchore_db_read_seconds"
                ).time() as _:
                    with db.session_scope() as dbsession:
                        anchore_record = db_anchore.get(session=dbsession)
            except Exception as err:
                logger.warn("unable to perform DB read probe - exception: " + str(err))

            if anchore_record:
                try:
                    with anchore_engine.subsys.metrics.get_summary_obj(
                        "anchore_db_write_seconds"
                    ).time() as _:
                        with db.session_scope() as dbsession:
                            anchore_record["record_state_val"] = str(time.time())
                            db_anchore.update_record(anchore_record, session=dbsession)

                except Exception as err:
                    logger.warn(
                        "unable to perform DB write probe - exception: " + str(err)
                    )

            try:
                with anchore_engine.subsys.metrics.get_summary_obj(
                    "anchore_db_readwrite_seconds"
                ).time() as _:
                    with db.session_scope() as dbsession:
                        anchore_record = db_anchore.get(session=dbsession)
                        anchore_record["record_state_val"] = str(time.time())
                        db_anchore.update_record(anchore_record, session=dbsession)
            except Exception as err:
                logger.warn(
                    "unable to perform DB read/write probe - exception: " + str(err)
                )

            # FS probes
            localconfig = anchore_engine.configuration.localconfig.get_config()
            try:
                tmpdir = localconfig["tmp_dir"]
                svfs = os.statvfs(tmpdir)
                available_bytes = svfs.f_bsize * svfs.f_bavail
                anchore_engine.subsys.metrics.gauge_set(
                    "anchore_tmpspace_available_bytes", available_bytes
                )
            except Exception as err:
                logger.warn(
                    "unable to detect available bytes probe - exception: " + str(err)
                )

        time.sleep(cycle_timer)


def handle_archive_tasks(*args, **kwargs):
    """

    Handles periodic scan tasks for archive rule processing

    :param args:
    :param kwargs:
    :return:
    """
    watcher = str(kwargs["mythread"]["taskType"])

    start_time = time.time()
    logger.debug("FIRING: " + str(watcher))
    task_id = None
    account_names = []
    try:
        logger.info("Starting analysis archive transition rule processor")
        with db.session_scope() as session:
            # Get all enabled accounts
            mgr = manager_factory.for_session(session)
            accounts = mgr.list_accounts(
                with_state=AccountStates.enabled, include_service=False
            )

            if accounts:
                account_names = [x["name"] for x in accounts]

            logger.debug("Found accounts {} with transition rules".format(accounts))

        for account in account_names:
            task = archiver.ArchiveTransitionTask(account)
            task_id = task.task_id
            logger.info(
                "Starting archive transition task {} for account {}".format(
                    task.task_id, account
                )
            )
            task.run()
            logger.info("Archive transition task {} complete".format(task.task_id))

    except Exception:
        logger.exception("Caught unexpected exception")
    finally:
        logger.debug(
            "Analysis archive task {} execution time: {} seconds".format(
                task_id, time.time() - start_time
            )
        )
        logger.debug("Sleeping until next cycle since no messages to process")

    return True


def handle_image_gc(*args, **kwargs):
    """
    Periodic handler for cleaning up images that are marked for deletion, can be extended to cover other states in the future
    Serializes image deletion across the board to minimize the load on database

    :param args:
    :param kwargs:
    :return:
    """
    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    try:
        # iterate over all images marked for deletion
        with db.session_scope() as dbsession:
            dbfilter = {"image_status": taskstate.queued_state("image_status")}
            queued_images = db_catalog_image.get_all_by_filter(
                session=dbsession, **dbfilter
            )

        for to_be_deleted in queued_images:
            try:
                account = to_be_deleted["userId"]
                digest = to_be_deleted["imageDigest"]

                logger.debug(
                    "Starting image gc for account id: %s, digest: %s"
                    % (account, digest)
                )

                with db.session_scope() as dbsession:
                    logger.debug("Checking image status one final time")
                    expected_status = taskstate.queued_state("image_status")
                    current_status = db_catalog_image.get_image_status(
                        account, digest, dbsession
                    )
                    if current_status and current_status == expected_status:
                        # set force to true since all deletion checks should be cleared at this point
                        retobj, httpcode = catalog_impl.do_image_delete(
                            account, to_be_deleted, dbsession, force=True
                        )
                        if httpcode != 200:
                            logger.warn(
                                "Image deletion failed with error: {}".format(retobj)
                            )
                    else:
                        logger.warn(
                            "Skipping image gc due to status check mismatch. account id: %s, digest: %s, current status: %s, expected status: %s"
                            % (account, digest, current_status, expected_status)
                        )
                # not necessary to state transition to deleted as the records should have gone
            except:
                logger.exception("Error deleting image, may retry on next cycle")
                # TODO state transition to faulty to avoid further usage?
    except Exception as err:
        logger.warn("failure in handler - exception: " + str(err))

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass

    if anchore_engine.subsys.metrics.is_enabled() and handler_success:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="success",
        )
    else:
        anchore_engine.subsys.metrics.summary_observe(
            "anchore_monitor_runtime_seconds",
            time.time() - timer,
            function=watcher,
            status="fail",
        )

    return True


click = 0
running = False
last_run = 0
system_user_auth = ("anchore-system", "")
# policy update check data
feed_sync_updated = False
bundle_user_last_updated = {}
bundle_user_is_updated = {}

default_lease_ttl = 60  # 1 hour ttl, should be more than enough in most cases


def watcher_func(*args, **kwargs):
    global system_user_auth

    while True:
        logger.debug("starting generic watcher")
        all_ready = anchore_engine.clients.services.common.check_services_ready(
            ["simplequeue"]
        )
        if not all_ready:
            logger.info("simplequeue service not yet ready, will retry")
        else:
            q_client = internal_client_for(SimpleQueueClient, userId=None)
            lease_id = None
            try:
                logger.debug("attempting dequeue")
                qobj = q_client.dequeue("watcher_tasks", max_wait_seconds=30)
                logger.debug("dequeue complete")

                if qobj:
                    logger.debug("got task from queue: " + str(qobj))
                    watcher = qobj["data"]["watcher"]
                    handler = watchers[watcher]["handler"]
                    args = []
                    kwargs = {"mythread": watchers[watcher]}

                    lease_id = watchers[watcher]["task_lease_id"]

                    # Old way
                    if not lease_id:
                        logger.debug(
                            "No task lease defined for watcher {}, initiating without lock protection".format(
                                watcher
                            )
                        )
                        handler(*args, **kwargs)
                    else:
                        simplequeue.run_target_with_lease(
                            None,
                            lease_id,
                            handler,
                            ttl=default_lease_ttl,
                            *args,
                            **kwargs,
                        )

                else:
                    logger.debug("nothing in queue")
            except (
                simplequeue.LeaseAcquisitionFailedError,
                simplequeue.LeaseUnavailableError,
            ) as e:
                logger.debug(
                    "Lease acquisition could not complete, but this is probably due to another process with the lease: {}".format(
                        e
                    )
                )
            except Exception as err:
                logger.warn("failed to process task this cycle: " + str(err))
        logger.debug("generic watcher done")
        time.sleep(5)


def schedule_watcher(watcher):
    global watchers, watcher_task_template, system_user_auth

    if watcher not in watchers:
        logger.warn(
            "input watcher {} not in list of available watchers {}".format(
                watcher, list(watchers.keys())
            )
        )
        return False

    if watchers[watcher]["taskType"]:
        logger.debug("should queue job: " + watcher)
        watcher_task = copy.deepcopy(watcher_task_template)
        watcher_task["watcher"] = watcher
        watcher_task["taskType"] = watchers[watcher]["taskType"]
        try:
            q_client = internal_client_for(SimpleQueueClient, userId=None)
            if not q_client.is_inqueue("watcher_tasks", watcher_task):
                qobj = q_client.enqueue("watcher_tasks", watcher_task)
                logger.debug(str(watcher_task) + ": init task queued: " + str(qobj))
            else:
                logger.debug(str(watcher_task) + ": init task already queued")

            watchers[watcher]["last_queued"] = time.time()
        except Exception as err:
            logger.warn("failed to enqueue watcher task: " + str(err))

    return True


def monitor_func(**kwargs):
    global click, running, last_queued, system_user_auth, watchers, last_run

    if click < 5:
        click = click + 1
        logger.debug("Catalog monitor starting in: " + str(5 - click))
        return True

    if running or ((time.time() - last_run) < kwargs["kick_timer"]):
        return True

    logger.debug("FIRING: catalog_monitor")
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        system_user_auth = localconfig["system_user_auth"]

        for watcher in list(watchers.keys()):
            if not watchers[watcher]["initialized"]:
                # first time
                if "cycle_timers" in kwargs and watcher in kwargs["cycle_timers"]:
                    try:
                        the_cycle_timer = watchers[watcher]["cycle_timer"]
                        min_cycle_timer = watchers[watcher]["min_cycle_timer"]
                        max_cycle_timer = watchers[watcher]["max_cycle_timer"]

                        config_cycle_timer = int(kwargs["cycle_timers"][watcher])
                        if config_cycle_timer < 0:
                            the_cycle_timer = abs(int(config_cycle_timer))
                        elif config_cycle_timer == 0:
                            watchers[watcher]["enabled"] = False
                            logger.debug(
                                "watcher '{}' has been explicitly disabled in config".format(
                                    watcher
                                )
                            )
                        elif config_cycle_timer < min_cycle_timer:
                            logger.warn(
                                "configured cycle timer for handler ("
                                + str(watcher)
                                + ") is less than the allowed min ("
                                + str(min_cycle_timer)
                                + ") - using allowed min"
                            )
                            the_cycle_timer = min_cycle_timer
                        elif config_cycle_timer > max_cycle_timer:
                            logger.warn(
                                "configured cycle timer for handler ("
                                + str(watcher)
                                + ") is greater than the allowed max ("
                                + str(max_cycle_timer)
                                + ") - using allowed max"
                            )
                            the_cycle_timer = max_cycle_timer
                        else:
                            the_cycle_timer = config_cycle_timer

                        watchers[watcher]["cycle_timer"] = the_cycle_timer
                    except Exception as err:
                        logger.warn(
                            "exception setting custom cycle timer for handler ("
                            + str(watcher)
                            + ") - using default"
                        )

                watchers[watcher]["initialized"] = True

            if watchers[watcher].get("enabled", True):
                if watcher not in watcher_threads:
                    if watchers[watcher]["taskType"]:
                        # spin up a generic task watcher
                        logger.debug("starting generic task thread")
                        watcher_threads[watcher] = threading.Thread(
                            target=watcher_func, args=[watcher], kwargs={}
                        )
                        watcher_threads[watcher].start()
                    else:
                        # spin up a specific looping watcher thread
                        watcher_threads[watcher] = threading.Thread(
                            target=watchers[watcher]["handler"],
                            args=watchers[watcher]["args"],
                            kwargs={"mythread": watchers[watcher]},
                        )
                        watcher_threads[watcher].start()

                all_ready = anchore_engine.clients.services.common.check_services_ready(
                    ["simplequeue"]
                )
                if not all_ready:
                    logger.info("simplequeue service not yet ready, will retry")
                elif (
                    time.time() - watchers[watcher]["last_queued"]
                    > watchers[watcher]["cycle_timer"]
                ):
                    rc = schedule_watcher(watcher)

    except Exception as err:
        logger.error(str(err))
    finally:
        logger.debug("FIRING DONE: catalog_monitor")
        running = False
        last_run = time.time()

    logger.debug("exiting monitor thread")


monitor_thread = None


def monitor(*args, **kwargs):
    global monitor_thread
    try:
        donew = False
        if monitor_thread:
            if monitor_thread.is_alive():
                logger.spew("MON: thread still running")
            else:
                logger.spew("MON: thread stopped running")
                donew = True
                monitor_thread.join()
                logger.spew(
                    "MON: thread joined: isAlive=" + str(monitor_thread.isAlive())
                )
        else:
            logger.spew("MON: no thread")
            donew = True

        if donew:
            logger.spew("MON: starting")
            monitor_thread = threading.Thread(target=monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))


class CatalogService(ApiService):
    __service_name__ = "catalog"
    __spec_dir__ = pkg_resources.resource_filename(__name__, "swagger")
    __monitor_fn__ = monitor

    def _register_instance_handlers(self):
        super()._register_instance_handlers()

        self.register_handler(LifeCycleStages.post_db, self._init_object_storage, {})
        self.register_handler(LifeCycleStages.post_register, self._init_policies, {})

    def _init_object_storage(self):
        try:
            did_init = object_store.initialize(
                self.configuration,
                manager_id=DEFAULT_OBJECT_STORE_MANAGER_ID,
                config_keys=[
                    DEFAULT_OBJECT_STORE_MANAGER_ID,
                    ALT_OBJECT_STORE_CONFIG_KEY,
                ],
                allow_legacy_fallback=True,
            )
            if not did_init:
                logger.warn(
                    "Unexpectedly found the object store already initialized. This is not an expected condition. Continuting with driver: {}".format(
                        object_store.get_manager().primary_client.__config_name__
                    )
                )
        except Exception as err:
            logger.exception(
                "Error initializing the object store: check catalog configuration"
            )
            raise err

        try:
            archive.initialize(self.configuration)

        except Exception as err:
            logger.exception(
                "Error initializing analysis archive: check catalog configuration"
            )
            raise err

    def _init_policies(self):
        """
        Ensure all accounts have a default policy in place
        :return:
        """

        obj_mgr = object_store.get_manager()

        with db.session_scope() as dbsession:
            mgr = manager_factory.for_session(dbsession)
            for account_dict in mgr.list_accounts(include_service=False):
                try:
                    logger.info("Initializing a new account")
                    userId = account_dict[
                        "name"
                    ]  # Old keys are userId, now that maps to account name
                    bundle_records = db_policybundle.get_all_byuserId(
                        userId, session=dbsession
                    )
                    if not bundle_records:
                        logger.debug(
                            "Account {} has no policy bundle - installing default".format(
                                userId
                            )
                        )

                        config = self.global_configuration

                        # What to do with each policy bundle
                        def process_bundle(policy_bundle, bundle):
                            bundle_url = obj_mgr.put_document(
                                userId, "policy_bundles", bundle["id"], bundle
                            )
                            policy_record = make_policy_record(
                                userId, bundle, policy_bundle["active"]
                            )
                            rc = db_policybundle.add(
                                policy_record["policyId"],
                                userId,
                                policy_bundle["active"],
                                policy_record,
                                session=dbsession,
                            )
                            if not rc:
                                raise Exception("policy bundle DB add failed")

                        # How to handle any exceptions form opening the bundle file or converting
                        # its contents to json
                        def process_exception(exception):
                            if isinstance(exception, IntegrityError):
                                logger.warn(
                                    "another process has already initialized, continuing"
                                )
                            else:
                                logger.error(
                                    "could not load up default bundle for user - exception: "
                                    + str(exception)
                                )

                        anchore_engine.configuration.localconfig.load_policy_bundles(
                            config, process_bundle, process_exception
                        )

                except Exception as err:
                    if isinstance(err, IntegrityError):
                        logger.warn(
                            "another process has already initialized, continuing"
                        )
                    else:
                        raise Exception(
                            "unable to initialize default user data - exception: "
                            + str(err)
                        )

    @staticmethod
    def get_image_content(account_id, content_type, image_digest):
        if content_type == "manifest":
            getter = ImageManifestContentGetter(account_id, content_type, image_digest)
        elif content_type == "dockerfile":
            getter = ImageDockerfileContentGetter(
                account_id, content_type, image_digest
            )
        else:
            getter = ImageContentGetter(account_id, content_type, image_digest)

        return getter.get()


def delete_import_operation(dbsession, operation: ImageImportOperation):
    """
    Execute the deletion path for an import operation

    :param dbsession:
    :param operation:
    :return:
    """
    logger.info("garbage collecting import operation: %s", operation.uuid)

    obj_mgr = object_store.get_manager()
    failed = False
    uuid = operation.uuid

    for content in operation.contents:
        try:
            logger.debug(
                "deleting import content digest %s of type %s for operation %s",
                content.digest,
                content.content_type,
                operation.uuid,
            )
            obj_mgr.delete_document(
                userId=operation.account,
                bucket=content.content_storage_bucket,
                archiveid=content.content_storage_key,
            )
            dbsession.delete(content)
            logger.debug(
                "deleted import content digest %s of type %s for operation %s successfully",
                content.digest,
                content.content_type,
                operation.uuid,
            )
        except:
            logger.debug_exception(
                "could not delete import content of type %s for operation %s with digest %s",
                content.content_type,
                operation.uuid,
                content.digest,
            )
            failed = True

    if not failed:
        dbsession.delete(operation)
    else:
        return operation

    logger.info("garbage collection of import operation %s complete", uuid)
    return None


def garbage_collect_imports():
    """
    Flush all imports that are in a state ready for collection

    :return:
    """

    # iterate over all imports ready for GC
    with db.session_scope() as dbsession:
        to_clean = dbsession.query(ImageImportOperation).filter(
            ImageImportOperation.status.in_(
                [
                    ImportState.invalidated,
                    ImportState.complete,
                    ImportState.failed,
                    ImportState.expired,
                ]
            )
        )

        for op in to_clean:
            try:
                logger.debug(
                    "Starting import operation gc for account id: %s, operation id: %s"
                    % (op.account, op.uuid)
                )
                delete_import_operation(dbsession, op)
            except:
                logger.exception("Error deleting image, may retry on next cycle")


def list_account_import_ops(account: str, session=None, limit: int = 1000):
    """
    Return list of import operations for the given account, but only the first limit count to keep memory use reasonable.

    :param account:
    :param session:
    :param limit:
    :return: list of ImageImportOperations objects
    """

    if session is None:
        raise ValueError("session is None")

    return (
        session.query(ImageImportOperation)
        .filter(ImageImportOperation.account == account)
        .limit(limit)
        .all()
    )


def delete_image_import_resource(
    account_name: str, record: ImageImportOperation, dbsession=None, force=True
):
    """
    A function with the correct signature for use in do_account_resources_delete but that wraps the existing
    delete_import_operation function

    :param account_name: the string name of the account owning the record
    :param record: the record to delete and its content
    :param force: bool included for function signature parity with other cleanup functions, but ignored as meaningless
    :return:
    """

    # Yes, weird, but function interface for the caller loop that calls this expects kwarg for dbsession
    if not dbsession:
        raise ValueError("Must have non-None db session")

    # Ensure that there isn't an unexpected mismatch here. This should definitely no be triggered unless there are
    # bugs elsewhere in the call chain
    if record.account != account_name:
        raise ValueError("account name does not match requested record to delete")

    delete_import_operation(dbsession, record)


def expire_imports():
    """
    Flush all imports that are in a state ready for collection
    :return:
    """

    # iterate over all imports ready for GC
    with db.session_scope() as dbsession:
        for operation in dbsession.query(ImageImportOperation).filter(
            ImageImportOperation.status.in_(
                [ImportState.pending, ImportState.processing]
            ),
            ImageImportOperation.expires_at < datetime.datetime.utcnow(),
        ):
            operation.status = ImportState.expired


def handle_import_gc(*args, **kwargs):
    """
    Cleanup import operations that are expired or complete and reclaim resources

    :param args:
    :param kwargs:
    :return:
    """

    watcher = str(kwargs["mythread"]["taskType"])
    handler_success = True

    timer = time.time()
    logger.debug("FIRING: " + str(watcher))

    try:
        garbage_collect_imports()
    except Exception as err:
        logger.warn("failure in handler - exception: " + str(err))

    try:
        expire_imports()
    except Exception as err:
        logger.warn("failure in handler - exception: " + str(err))

    logger.debug("FIRING DONE: " + str(watcher))
    try:
        kwargs["mythread"]["last_return"] = handler_success
    except:
        pass


watchers = {
    "image_watcher": {
        "handler": handle_image_watcher,
        "task_lease_id": "image_watcher",
        "taskType": "handle_image_watcher",
        "args": [],
        "cycle_timer": 600,
        "min_cycle_timer": 300,
        "max_cycle_timer": 86400 * 7,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "repo_watcher": {
        "handler": handle_repo_watcher,
        "task_lease_id": "repo_watcher",
        "taskType": "handle_repo_watcher",
        "args": [],
        "cycle_timer": 60,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400 * 7,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "policy_eval": {
        "handler": handle_policyeval,
        "task_lease_id": "policy_eval",
        "taskType": "handle_policyeval",
        "args": [],
        "cycle_timer": 300,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400 * 2,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "analyzer_queue": {
        "handler": handle_analyzer_queue,
        "task_lease_id": "analyzer_queue",
        "taskType": "handle_analyzer_queue",
        "args": [],
        "cycle_timer": 5,
        "min_cycle_timer": 1,
        "max_cycle_timer": 7200,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "notifications": {
        "handler": handle_notifications,
        "task_lease_id": "notifications",
        "taskType": "handle_notifications",
        "args": [],
        "cycle_timer": 10,
        "min_cycle_timer": 10,
        "max_cycle_timer": 86400 * 2,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "vulnerability_scan": {
        "handler": handle_vulnerability_scan,
        "task_lease_id": "vulnerability_scan",
        "taskType": "handle_vulnerability_scan",
        "args": [],
        "cycle_timer": 300,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400 * 2,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "account_resource_cleanup": {
        "handler": handle_account_resource_cleanup,
        "task_lease_id": "account_resource_cleanup",
        "taskType": "handle_account_resource_cleanup",
        "args": [],
        "cycle_timer": 30,
        "min_cycle_timer": 30,
        "max_cycle_timer": 30,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "service_watcher": {
        "handler": handle_service_watcher,
        "task_lease_id": False,
        "taskType": None,
        "args": [],
        "cycle_timer": 10,
        "min_cycle_timer": 1,
        "max_cycle_timer": 300,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "service_heartbeat": {
        "handler": anchore_engine.subsys.servicestatus.handle_service_heartbeat,
        "task_lease_id": False,
        "taskType": None,
        "args": [CatalogService.__service_name__],
        "cycle_timer": 60,
        "min_cycle_timer": 60,
        "max_cycle_timer": 60,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "handle_metrics": {
        "handler": handle_metrics,
        "task_lease_id": False,
        "taskType": None,
        "args": [],
        "cycle_timer": 60,
        "min_cycle_timer": 60,
        "max_cycle_timer": 60,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "archive_tasks": {
        "handler": handle_archive_tasks,
        "task_lease_id": "archive_transitions",
        "taskType": "handle_archive_tasks",
        "args": [],
        "cycle_timer": 43200,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400 * 5,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "image_gc": {
        "handler": handle_image_gc,
        "task_lease_id": "image_gc",
        "taskType": "handle_image_gc",
        "args": [],
        "cycle_timer": 60,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
    "import_gc": {
        "handler": handle_import_gc,
        "task_lease_id": "import_gc",
        "taskType": "handle_import_gc",
        "args": [],
        "cycle_timer": 60,
        "min_cycle_timer": 60,
        "max_cycle_timer": 86400,
        "last_queued": 0,
        "last_return": False,
        "initialized": False,
    },
}

watcher_task_template = {
    "taskType": None,
    "watcher": None,
}
watcher_threads = {}
