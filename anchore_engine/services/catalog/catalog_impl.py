import base64
import collections
import hashlib
import json
import re
import time
from collections import namedtuple

from dateutil import parser as dateparser

import anchore_engine.apis.authorization
import anchore_engine.common
import anchore_engine.common.helpers
import anchore_engine.common.images
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.events
import anchore_engine.subsys.metrics
import anchore_engine.subsys.object_store.manager
from anchore_engine.apis.exceptions import AnchoreApiError, BadRequest
from anchore_engine.auth import aws_ecr
from anchore_engine.clients import docker_registry
from anchore_engine.clients.services import internal_client_for
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.db import (
    db_catalog_image,
    db_events,
    db_policybundle,
    db_policyeval,
    db_registries,
    db_services,
    db_subscriptions,
    session_scope,
)
from anchore_engine import utils as anchore_utils
from anchore_engine.services.catalog import utils
from anchore_engine.util.docker import parse_dockerimage_string
from anchore_engine.subsys import logger, notifications, object_store, taskstate

DeleteImageResponse = namedtuple("DeleteImageResponse", ["digest", "status", "detail"])


def policy_engine_image_load(client, imageUserId, imageId, imageDigest):
    """
    Helper function for constructing the call to the PE for loading images

    :param client:
    :param imageUserId:
    :param imageId:
    :param imageDigest:
    :return:
    """
    try:
        fetch_url = "catalog://{user_id}/analysis_data/{digest}".format(
            user_id=imageUserId, digest=imageDigest
        )

        logger.debug(
            "policy engine request (image add): img_user_id={}, image_id={}, fetch_url={}".format(
                imageUserId, imageId, fetch_url
            )
        )
        resp = client.ingress_image(
            user_id=imageUserId, image_id=imageId, analysis_fetch_url=fetch_url
        )
        logger.spew("policy engine response (image add): " + str(resp))
    except Exception as err:
        logger.error("failed to add/check image: " + str(err))
        raise err

    return resp


def registry_lookup(dbsession, request_inputs):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None

    try:
        for t in ["tag", "digest"]:
            if t in params:
                input_string = params[t]
                if input_string:
                    input_type = t
                    image_info = anchore_engine.common.images.get_image_info(
                        userId,
                        "docker",
                        input_string,
                        registry_lookup=False,
                        registry_creds=(None, None),
                    )
                    break

        if not image_info:
            httpcode = 500
            raise Exception("need 'tag' or 'digest' in url params")
        else:
            try:
                registry_creds = db_registries.get_byuserId(userId, session=dbsession)
                try:
                    refresh_registry_creds(registry_creds, dbsession)
                except Exception as err:
                    logger.warn(
                        "failed to refresh registry credentials - exception: "
                        + str(err)
                    )

                digest, manifest = anchore_engine.common.images.lookup_registry_image(
                    userId, image_info, registry_creds
                )
                return_object["digest"] = (
                    image_info["registry"] + "/" + image_info["repo"] + "@" + digest
                )
                return_object["manifest"] = manifest
                httpcode = 200
            except Exception as err:
                httpcode = 404
                raise Exception("cannot lookup image in registry - detail: " + str(err))
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def repo(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    fulltag = None
    regrepo = False
    if params and "regrepo" in params:
        regrepo = params["regrepo"]

    autosubscribe = False
    if params and "autosubscribe" in params:
        autosubscribe = params["autosubscribe"]

    lookuptag = "latest"

    dryrun = False
    if params and "dryrun" in params:
        dryrun = params["dryrun"]

    fulltag = regrepo + ":" + lookuptag

    try:
        if method == "POST":
            image_info = anchore_engine.common.images.get_image_info(
                userId,
                "docker",
                fulltag,
                registry_lookup=False,
                registry_creds=(None, None),
            )

            registry_creds = db_registries.get_byuserId(userId, session=dbsession)
            try:
                refresh_registry_creds(registry_creds, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

            repotags = []
            try:
                repotags = docker_registry.get_repo_tags(
                    userId, image_info, registry_creds=registry_creds
                )
            except Exception as err:
                httpcode = 404
                logger.warn(
                    "no tags could be added from input regrepo ("
                    + str(regrepo)
                    + ") - exception: "
                    + str(err)
                )
                raise Exception(
                    "no tags could be added from input regrepo (" + str(regrepo) + ")"
                )

            try:
                regrepo = image_info["registry"] + "/" + image_info["repo"]

                if dryrun:
                    subscription_records = [
                        db_subscriptions.create_without_saving(
                            userId=userId,
                            subscription_key=regrepo,
                            subscription_type="repo_update",
                            inobj={
                                "active": False,
                                "subscription_value": json.dumps(
                                    {
                                        "autosubscribe": autosubscribe,
                                        "lookuptag": lookuptag,
                                        "tagcount": len(repotags),
                                    }
                                ),
                            },
                        )
                    ]
                else:
                    dbfilter = {
                        "subscription_type": "repo_update",
                        "subscription_key": regrepo,
                    }

                    subscription_records = db_subscriptions.get_byfilter(
                        userId, session=dbsession, **dbfilter
                    )
                    if not subscription_records:
                        rc = db_subscriptions.add(
                            userId,
                            regrepo,
                            "repo_update",
                            {
                                "active": True,
                                "subscription_value": json.dumps(
                                    {
                                        "autosubscribe": autosubscribe,
                                        "lookuptag": lookuptag,
                                        "tagcount": len(repotags),
                                    }
                                ),
                            },
                            session=dbsession,
                        )
                        if not rc:
                            raise Exception("adding required subscription failed")

                    else:
                        # update new metadata
                        subscription_record = subscription_records[0]
                        subscription_value = json.loads(
                            subscription_record["subscription_value"]
                        )
                        subscription_value["autosubscribe"] = autosubscribe
                        subscription_value["lookuptag"] = lookuptag
                        rc = db_subscriptions.upsert(
                            userId,
                            regrepo,
                            "repo_update",
                            {"subscription_value": json.dumps(subscription_value)},
                            session=dbsession,
                        )

                    subscription_records = db_subscriptions.get_byfilter(
                        userId, session=dbsession, **dbfilter
                    )
            except Exception as err:
                logger.exception(
                    "could not add the required subscription to anchore-engine"
                )
                httpcode = 500
                raise Exception(
                    "could not add the required subscription to anchore-engine"
                )

            if not subscription_records:
                httpcode = 500
                raise Exception(
                    "unable to add/update subscripotion records in anchore-engine"
                )

            return_object = subscription_records
            return_object[0]["subscription_value"] = json.dumps(
                {
                    "autosubscribe": autosubscribe,
                    "repotags": repotags,
                    "tagcount": len(repotags),
                    "lookuptag": lookuptag,
                }
            )

            httpcode = 200

            # check and kick a repo watcher task if necessary
            try:
                rc = anchore_engine.services.catalog.service.schedule_watcher(
                    "repo_watcher"
                )
                logger.debug("scheduled repo_watcher task")
            except Exception as err:
                logger.warn("failed to schedule repo_watcher task: " + str(err))
                pass

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def image_tags(account_id, dbsession, image_status):
    return_object = []
    httpcode = 500

    try:
        return_object = db_catalog_image.get_all_tagsummary(
            account_id, session=dbsession, image_status=image_status
        )
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def image(dbsession, request_inputs, bodycontent=None):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None

    # set up params
    registry_lookup = False
    if params and "registry_lookup" in params:
        registry_lookup = params["registry_lookup"]

    history = False
    if params and "history" in params:
        history = params["history"]

    image_status = params.get("image_status") if params else None
    analysis_status = params.get("analysis_status") if params else None

    httpcode = 500
    input_string = None
    try:
        for t in ["tag", "digest", "imageId"]:
            if t in params:
                input_string = params[t]
                if input_string:
                    input_type = t
                    image_info = anchore_engine.common.images.get_image_info(
                        userId,
                        "docker",
                        input_string,
                        registry_lookup=False,
                        registry_creds=(None, None),
                    )
                    break

        image_status_filter = (
            image_status if image_status and image_status != "all" else None
        )
        analysis_status_filter = (
            analysis_status if analysis_status and analysis_status != "all" else None
        )

        if method == "GET":
            if not input_string:
                httpcode = 200
                return_object = db_catalog_image.get_all_byuserId(
                    userId,
                    session=dbsession,
                    image_status_filter=image_status_filter,
                    analysis_status_filter=analysis_status_filter,
                )
            else:
                if registry_lookup:
                    try:
                        registry_creds = db_registries.get_byuserId(
                            userId, session=dbsession
                        )
                        try:
                            refresh_registry_creds(registry_creds, dbsession)
                        except Exception as err:
                            logger.warn(
                                "failed to refresh registry credentials - exception: "
                                + str(err)
                            )
                        try:
                            image_info = anchore_engine.common.images.get_image_info(
                                userId,
                                "docker",
                                input_string,
                                registry_lookup=True,
                                registry_creds=registry_creds,
                            )
                        except Exception as err:
                            fail_event = (
                                anchore_engine.subsys.events.ImageRegistryLookupFailed(
                                    user_id=userId,
                                    image_pull_string=input_string,
                                    data=err.__dict__,
                                )
                            )
                            try:
                                add_event(fail_event, dbsession)
                            except:
                                logger.warn(
                                    "Ignoring error creating image registry lookup event"
                                )
                            raise err
                    except Exception as err:
                        httpcode = 404
                        raise Exception(
                            "cannot perform registry lookup - exception: " + str(err)
                        )

                if image_info:
                    try:
                        if history:
                            if input_type == "tag":
                                filterkeys = ["registry", "repo", "tag", "imageId"]
                            else:
                                raise Exception(
                                    "cannot use history without specifying an input tag"
                                )
                        else:
                            filterkeys = [
                                "registry",
                                "repo",
                                "tag",
                                "digest",
                                "imageId",
                            ]

                        dbfilter = {}
                        for k in filterkeys:
                            if k in image_info and image_info[k]:
                                dbfilter[k] = image_info[k]

                        logger.debug(
                            "image DB lookup filter: " + json.dumps(dbfilter, indent=4)
                        )
                        if history:
                            image_records = db_catalog_image.get_byimagefilter(
                                userId,
                                "docker",
                                dbfilter=dbfilter,
                                image_status=image_status_filter,
                                analysis_status=analysis_status_filter,
                                session=dbsession,
                            )
                        else:
                            image_records = db_catalog_image.get_byimagefilter(
                                userId,
                                "docker",
                                dbfilter=dbfilter,
                                image_status=image_status_filter,
                                analysis_status=analysis_status_filter,
                                onlylatest=True,
                                session=dbsession,
                            )

                        if image_records:
                            return_object = image_records
                            httpcode = 200
                        else:
                            httpcode = 404
                            raise Exception("image data not found in DB")
                    except Exception as err:
                        raise err
                else:
                    httpcode = 404
                    raise Exception("image not found in DB")

        elif method == "POST":
            return_object, httpcode = image_post(
                userId,
                input_type,
                params,
                bodycontent,
                dbsession,
                image_info,
                input_string,
            )
    except AnchoreApiError as err:
        logger.exception("Error processing image request")
        return_object = anchore_engine.common.helpers.make_response_error(
            err.message, in_httpcode=err.__response_code__, details=err.detail
        )
        httpcode = err.__response_code__
    except Exception as err:
        logger.exception("Error processing image request")
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def image_post(
    account_id, input_type, params, bodycontent, dbsession, image_info, input_string
):
    """
    :param account_id: the account id string
    :param input_type: a string that describes what type of input we're processing. Possible values: [tag, digest, imageId], Must be tag or imageId for this method to work
    :param params: dict containing the following keys:
        - allow_dockerfile_update
        - tag
        - digest
        - created_at
    :param bodycontent: dict containing the following keys:
        - dockerfile (b64 encoded)
        - annotations
    :param dbsession: sqlalchemy database session object
    :param image_info: dict containing the following required keys:
        - registry
        - repo
        - tag
        - manifest
        - compressed_size
        - parentmanifest
        - digest
        - fulltag
        - imageId
        - created_at_override
    :param input_string: the tag or imageId of the image being added

    """
    if input_type == "digest":
        raise Exception("catalog add requires a tag string to determine registry/repo")

    allow_dockerfile_update = params.get("allow_dockerfile_update", False)

    jsondata = {}
    if bodycontent:
        jsondata = bodycontent

    dockerfile, dockerfile_mode = get_dockerfile_info(jsondata)

    annotations = jsondata.get("annotations", {})

    image_record = {}
    registry_creds = get_and_refresh_registry_creds(account_id, dbsession)

    (
        image_info_overrides,
        input_string,
    ) = resolve_image_info_overrides_and_input_string(params, image_info, input_string)
    logger.debug("INPUT STRING: {}".format(input_string))
    logger.debug("INPUT IMAGE INFO: {}".format(image_info))
    logger.debug("INPUT IMAGE INFO OVERRIDES: {}".format(image_info_overrides))
    image_info = resolve_final_image_info(
        account_id, input_string, registry_creds, dbsession, image_info_overrides
    )

    logger.debug("INPUT FINAL IMAGE INFO: {}".format(image_info))

    manifest = get_manifest(image_info)

    # fail add if image is too large
    validate_image_size(image_info)

    parent_manifest = json.dumps(image_info.get("parentmanifest", {}))

    logger.debug("ADDING/UPDATING IMAGE IN IMAGE POST: " + str(image_info))

    # Check for dockerfile updates to an existing image
    if (
        not allow_dockerfile_update
        and dockerfile
        and dockerfile_mode.lower() == "actual"
    ):
        found_img = db_catalog_image.get(
            imageDigest=image_info["digest"],
            userId=account_id,
            session=dbsession,
        )
        if found_img:
            raise BadRequest(
                "Cannot specify dockerfile for an image that already exists unless using force=True for re-analysis",
                detail={
                    "digest": image_info["digest"],
                    "tag": image_info["fulltag"],
                },
            )

    image_records = add_or_update_image(
        dbsession,
        account_id,
        image_info["imageId"],
        tags=[image_info["fulltag"]],
        digests=[image_info["fulldigest"]],
        parentdigest=image_info.get("parentdigest", None),
        created_at=image_info.get("created_at_override", None),
        dockerfile=dockerfile,
        dockerfile_mode=dockerfile_mode,
        manifest=manifest,
        parent_manifest=parent_manifest,
        annotations=annotations,
    )
    if image_records:
        image_record = image_records[0]

    if image_record:
        httpcode = 200
        return_object = image_record
    else:
        raise Exception("could not add input image")

    return return_object, httpcode


def get_dockerfile_info(jsondata):
    dockerfile = None
    dockerfile_mode = None
    if "dockerfile" in jsondata:
        dockerfile = jsondata["dockerfile"]
        try:
            # this is a check to ensure the input is b64 encoded
            base64.decodebytes(dockerfile.encode("utf-8"))
            dockerfile_mode = "Actual"
        except Exception as err:
            raise Exception(
                "input dockerfile data must be base64 encoded - exception on decode: "
                + str(err)
            )
    return dockerfile, dockerfile_mode


def resolve_image_info_overrides_and_input_string(params, image_info, input_string):
    image_info_overrides = {}

    input_tag = params.get("tag", None)
    input_digest = params.get("digest", None)
    if input_tag and input_digest:
        input_fulldigest = "{}/{}@{}".format(
            image_info["registry"], image_info["repo"], input_digest
        )
        image_info_overrides["fulltag"] = input_tag
        image_info_overrides["tag"] = image_info["tag"]
        if params.get("created_at", None):
            image_info_overrides["created_at_override"] = params.get("created_at")
        input_string = input_fulldigest
    return image_info_overrides, input_string


def resolve_final_image_info(
    account_id, input_string, registry_creds, dbsession, image_info_overrides
):
    try:
        image_info = anchore_engine.common.images.get_image_info(
            account_id,
            "docker",
            input_string,
            registry_lookup=True,
            registry_creds=registry_creds,
        )
    except Exception as err:
        fail_event = anchore_engine.subsys.events.ImageRegistryLookupFailed(
            user_id=account_id,
            image_pull_string=input_string,
            data=err.__dict__,
        )
        try:
            add_event(fail_event, dbsession)
        except Exception:
            logger.warn("Ignoring error creating image registry lookup event")
        raise err

    if image_info_overrides:
        image_info.update(image_info_overrides)

    return image_info


def validate_image_size(image_info):
    if not is_image_valid_size(image_info):
        localconfig = anchore_engine.configuration.localconfig.get_config()
        raise BadRequest(
            "Image size is too large based on max size specified in the configuration",
            detail={
                "requested_image_compressed_size_mb": anchore_utils.bytes_to_mb(
                    image_info["compressed_size"], round_to=2
                ),
                "max_compressed_image_size_mb": localconfig.get(
                    "max_compressed_image_size_mb"
                ),
            },
        )


def get_manifest(image_info):
    if "manifest" in image_info:
        manifest = json.dumps(image_info["manifest"])
    else:
        raise Exception("no manifest from get_image_info")
    return manifest


def image_imageDigest(dbsession, request_inputs, imageDigest, bodycontent=None):
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    image_info = None
    input_type = None

    try:
        if method == "GET":
            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
            if image_record:
                httpcode = 200
                return_object = image_record
            else:
                httpcode = 404
                raise Exception("image not found in DB")

        elif method == "DELETE":
            return_object, httpcode = _queue_image_for_deletion(
                userId, imageDigest, dbsession, force=params["force"]
            )
        elif method == "PUT":
            # update an image

            jsondata = {}
            if bodycontent:
                jsondata = bodycontent

            updated_image_record = jsondata

            image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)
            if image_record:
                rc = db_catalog_image.update_record(
                    updated_image_record, session=dbsession
                )
                image_record = db_catalog_image.get(
                    imageDigest, userId, session=dbsession
                )

                httpcode = 200
                return_object = [image_record]
            else:
                httpcode = 404
                raise Exception("image not found")

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def subscriptions(dbsession, request_inputs, subscriptionId=None, bodycontent=None):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    subscription_key_filter = params.get("subscription_key", None)
    subscription_type_filter = params.get("subscription_type", None)

    try:
        logger.debug(
            "looking up subscription record: " + userId + " : " + str(subscriptionId)
        )

        if method == "GET":

            # set up the filter based on input
            dbfilter = {}
            if subscriptionId:
                dbfilter["subscription_id"] = subscriptionId
            else:
                if subscription_key_filter:
                    dbfilter["subscription_key"] = subscription_key_filter
                if subscription_type_filter:
                    if (
                        subscription_type_filter
                        not in anchore_engine.common.subscription_types
                    ):
                        httpcode = 400
                        raise Exception(
                            "%s is not a supported subscription type"
                            % subscription_type_filter
                        )
                    else:
                        dbfilter["subscription_type"] = subscription_type_filter

            records = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )
            if not records:
                httpcode = 200
                return_object = []
                # raise Exception("subscriptions not found in DB")
            else:
                return_object = records
                httpcode = 200

        elif method == "DELETE":
            if not subscriptionId:
                raise Exception("no subscriptionId passed in to delete")

            httpcode = 200
            return_object = True

            subscription_record = db_subscriptions.get(
                userId, subscriptionId, session=dbsession
            )
            if subscription_record:
                rc, httpcode = do_subscription_delete(
                    userId, subscription_record, dbsession, force=True
                )
                if httpcode not in list(range(200, 299)):
                    raise Exception(str(rc))

        elif method == "POST":
            subscriptiondata = bodycontent if bodycontent is not None else {}

            subscription_key = subscription_type = None
            if "subscription_key" in subscriptiondata:
                subscription_key = subscriptiondata["subscription_key"]
            if "subscription_type" in subscriptiondata:
                subscription_type = subscriptiondata["subscription_type"]
                if subscription_type not in anchore_engine.common.subscription_types:
                    httpcode = 400
                    raise Exception(
                        "%s is not a supported subscription type" % subscription_type
                    )

            if not subscription_key or not subscription_type:
                httpcode = 500
                raise Exception(
                    "body does not contain both subscription_key and subscription_type"
                )

            dbfilter = {
                "subscription_key": subscription_key,
                "subscription_type": subscription_type,
            }
            subscription_record = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )
            if subscription_record:
                httpcode = 500
                raise Exception("subscription already exists in DB")

            rc = db_subscriptions.add(
                userId,
                subscription_key,
                subscription_type,
                subscriptiondata,
                session=dbsession,
            )
            return_object = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )
            httpcode = 200

        elif method == "PUT":
            subscriptiondata = bodycontent if bodycontent is not None else {}

            subscription_record = subscription_key = subscription_type = None
            dbfilter = {}
            if subscriptionId:
                subscription_record = db_subscriptions.get(
                    userId, subscriptionId, session=dbsession
                )

                subscription_key = subscription_record["subscription_key"]
                subscription_type = subscription_record["subscription_type"]

                dbfilter["subscription_id"] = subscriptionId
            else:
                if "subscription_key" in subscriptiondata:
                    subscription_key = subscriptiondata["subscription_key"]
                if "subscription_type" in subscriptiondata:
                    subscription_type = subscriptiondata["subscription_type"]
                    if (
                        subscription_type
                        not in anchore_engine.common.subscription_types
                    ):
                        httpcode = 400
                        raise Exception(
                            "%s is not a supported subscription type"
                            % subscription_type_filter
                        )

                if not subscription_key or not subscription_type:
                    raise Exception(
                        "body does not contain both subscription_key and subscription_type"
                    )

                dbfilter = {
                    "subscription_key": subscription_key,
                    "subscription_type": subscription_type,
                }
                subscription_record = db_subscriptions.get_byfilter(
                    userId, session=dbsession, **dbfilter
                )

            if not subscription_record:
                httpcode = 404
                raise Exception("subscription to update does not exist in DB")

            rc = db_subscriptions.upsert(
                userId,
                subscription_key,
                subscription_type,
                subscriptiondata,
                session=dbsession,
            )
            return_object = db_subscriptions.get_byfilter(
                userId, session=dbsession, **dbfilter
            )
            httpcode = 200

    except Exception as err:
        logger.exception("Error handling subscriptions")
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def events(dbsession, request_inputs, bodycontent=None):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    try:
        jsondata = {}
        if bodycontent:
            try:
                jsondata = bodycontent
            except Exception as err:
                raise err

        if method == "GET":
            dbfilter = dict()

            if params.get("source_servicename", None):
                dbfilter["source_servicename"] = params.get("source_servicename")

            if params.get("source_hostid", None):
                dbfilter["source_hostid"] = params.get("source_hostid")

            if params.get("resource_type", None):
                dbfilter["resource_type"] = params.get("resource_type")

            if params.get("resource_id", None):
                dbfilter["resource_id"] = params.get("resource_id")

            if params.get("level", None):
                dbfilter["level"] = params.get("level")

            since = None
            if params.get("since", None):
                try:
                    since = dateparser.parse(params.get("since"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value for since query parameter, must be valid datetime string"
                    )

            before = None
            if params.get("before", None):
                try:
                    before = dateparser.parse(params.get("before"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value before query parameter, must be valid datetime string"
                    )

                if since and since >= before:
                    httpcode = 400
                    raise Exception(
                        "Invalid values for since and before query parameters. since must be smaller than before timestamp"
                    )

            page = 0
            if params.get("page", None) is not None:
                try:
                    page = int(params.get("page"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value for page query parameter, must be valid integer greater than 0"
                    )

            if page < 1:
                httpcode = 400
                raise Exception("page must be a valid integer greater than 0")

            limit = 0
            if params.get("limit", None) is not None:
                try:
                    limit = int(params.get("limit"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value limit query parameter, must be valid integer between 1 and 1000"
                    )

            if limit < 1 or limit > 1000:
                httpcode = 400
                raise Exception("limit must be valid integer between 1 and 1000")

            event_type = params.get("event_type")
            if event_type:
                event_type = event_type.lower()
                if not re.match(r"[a-z0-9-_.*]+", event_type):
                    httpcode = 400
                    raise Exception(
                        'Unacceptable chars in event_type. Must match regex "[a-z0-9-_.*]+"'
                    )

            ret = db_events.get_byfilter(
                userId=userId,
                session=dbsession,
                event_type=event_type,
                since=since,
                before=before,
                page=page,
                limit=limit,
                **dbfilter
            )
            if not ret:
                httpcode = 404
                raise Exception("events not found in DB")
            else:
                return_object = ret
                httpcode = 200

        elif method == "DELETE":
            dbfilter = dict()

            if params.get("level", None):
                dbfilter["level"] = params.get("level")

            since = None
            if params.get("since", None):
                try:
                    since = dateparser.parse(params.get("since"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value for since query parameter, must be valid datetime string"
                    )

            before = None
            if params.get("before", None):
                try:
                    before = dateparser.parse(params.get("before"))
                except:
                    httpcode = 400
                    raise Exception(
                        "Invalid value before query parameter, must be valid datetime string"
                    )

            ret = db_events.delete_byfilter(
                userId=userId, session=dbsession, since=since, before=before, **dbfilter
            )

            httpcode = 200
            return_object = ret

        elif method == "POST":
            record = add_event_json(jsondata, dbsession, quiet=False)

            if record:
                httpcode = 200
                return_object = record

            else:
                httpcode = 500
                raise Exception("Cannot create event")

    except Exception as err:
        logger.exception("Error in events handler")
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def events_eventId(dbsession, request_inputs, eventId):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    try:
        if method == "GET":
            ret = db_events.get_byevent_id(
                userId=userId, eventId=eventId, session=dbsession
            )
            if not ret:
                httpcode = 404
                raise Exception("Event not found")
            else:
                return_object = ret
                httpcode = 200
        elif method == "DELETE":
            ret = db_events.delete_byevent_id(
                userId=userId, eventId=eventId, session=dbsession
            )
            if not ret:
                httpcode = 404
                raise Exception("Event not found")
            else:
                return_object = True
                httpcode = 200

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system(dbsession, request_inputs):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    try:
        httpcode = 200
        return_object = ["services", "registries"]
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system_services(dbsession, request_inputs):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        return_object = service_records
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system_services_servicename(dbsession, request_inputs, inservicename):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        for service_record in service_records:
            servicename = service_record["servicename"]
            if servicename == inservicename:
                return_object.append(service_record)
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system_services_servicename_hostId(
    dbsession, request_inputs, inservicename, inhostId
):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = []
    httpcode = 500

    try:
        service_records = db_services.get_all(session=dbsession)
        for service_record in service_records:
            servicename = service_record["servicename"]
            if servicename == inservicename:
                hostId = service_record["hostid"]
                if hostId == inhostId:
                    if method == "GET":
                        return_object = [service_record]
                        httpcode = 200
                    elif method == "DELETE":
                        if service_record["status"]:
                            httpcode = 409
                            raise Exception("cannot delete an active service")
                        else:
                            db_services.delete(hostId, servicename, session=dbsession)
                            return_object = True
                            httpcode = 200

        if not return_object:
            httpcode = 404
            raise Exception(
                "servicename/host_id ("
                + str(inservicename)
                + "/"
                + str(inhostId)
                + ") not found in anchore-engine"
            )

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system_registries(dbsession, request_inputs, bodycontent={}):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = []
    httpcode = 500

    try:
        if method == "GET":
            registry_records = db_registries.get_byuserId(userId, session=dbsession)
            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

            return_object = registry_records
            httpcode = 200
        elif method == "POST":
            registrydata = bodycontent
            validate = params.get("validate", True)

            if "registry" in registrydata:
                registry = registrydata["registry"]
            else:
                httpcode = 500
                raise Exception("body does not contain registry key")

            registry_records = db_registries.get(registry, userId, session=dbsession)
            if registry_records:
                httpcode = 500
                raise Exception("registry already exists in DB")

            localconfig = anchore_engine.configuration.localconfig.get_config()
            if (
                registrydata["registry_user"] == "awsauto"
                or registrydata["registry_pass"] == "awsauto"
            ) and not localconfig["allow_awsecr_iam_auto"]:
                httpcode = 406
                raise Exception("'awsauto' is not enabled in service configuration")

            # attempt to validate on registry add before any DB / cred refresh is done - only support docker_v2 registry validation presently at this point
            if validate and registrydata.get("registry_type", False) in ["docker_v2"]:
                try:
                    registry_status = docker_registry.ping_docker_registry(registrydata)
                except Exception as err:
                    httpcode = 406
                    raise Exception(
                        "cannot ping supplied registry with supplied credentials - exception: {}".format(
                            str(err)
                        )
                    )

            if not registrydata.get("registry_name", None):
                registrydata["registry_name"] = registry

            rc = db_registries.add(registry, userId, registrydata, session=dbsession)
            registry_records = db_registries.get(registry, userId, session=dbsession)

            try:
                refresh_registry_creds(registry_records, dbsession)

                # perform validation if the refresh/setup is successful
                if validate:
                    for registry_record in registry_records:
                        try:
                            registry_status = docker_registry.ping_docker_registry(
                                registry_records[0]
                            )
                        except Exception as err:
                            httpcode = 406
                            raise Exception(
                                "cannot ping supplied registry with supplied credentials - exception: {}".format(
                                    str(err)
                                )
                            )
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )
                # if refresh fails for any reason (and validation is requested), remove the registry from the DB and raise a fault
                if validate:
                    db_registries.delete(registry, userId, session=dbsession)
                    httpcode = 406
                    raise Exception(
                        "cannot refresh credentials for supplied registry, with supplied credentials - exception: {}".format(
                            str(err)
                        )
                    )

            return_object = registry_records
            httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def get_and_refresh_registry_creds(account_id, dbsession):
    registry_creds = db_registries.get_byuserId(account_id, session=dbsession)
    try:
        refresh_registry_creds(registry_creds, dbsession)
    except Exception as err:
        logger.warn("failed to refresh registry credentials - exception: " + str(err))
    return registry_creds


def refresh_registry_creds(registry_records, dbsession):

    for registry_record in registry_records:

        logger.debug(
            "checking registry for up-to-date: "
            + str(registry_record["userId"])
            + " : "
            + str(registry_record["registry"])
            + " : "
            + str(registry_record["registry_type"])
        )
        if "registry_type" in registry_record and registry_record["registry_type"] in [
            "awsecr"
        ]:
            if registry_record["registry_type"] == "awsecr":
                dorefresh = True
                if registry_record["registry_meta"]:
                    ecr_data = json.loads(registry_record["registry_meta"])
                    expiresAt = ecr_data["expiresAt"]
                    if time.time() < expiresAt:
                        dorefresh = False

                if dorefresh:
                    registry_parts = registry_record["registry"].split("/", 1)
                    registry = registry_parts[0]

                    logger.debug(
                        "refreshing ecr registry: "
                        + str(registry_record["userId"])
                        + " : "
                        + str(registry_record["registry"])
                    )
                    ecr_data = aws_ecr.refresh_ecr_credentials(
                        registry,
                        registry_record["registry_user"],
                        registry_record["registry_pass"],
                    )
                    registry_record["registry_meta"] = json.dumps(ecr_data)
                    db_registries.update_record(registry_record, session=dbsession)

        logger.debug(
            "registry up-to-date: "
            + str(registry_record["userId"])
            + " : "
            + str(registry_record["registry"])
            + " : "
            + str(registry_record["registry_type"])
        )
    return True


def system_registries_registry(dbsession, request_inputs, registry, bodycontent={}):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = []
    httpcode = 500

    try:
        if method == "GET":
            registry_records = db_registries.get(registry, userId, session=dbsession)
            if not registry_records:
                httpcode = 404
                raise Exception("registry not found in DB")

            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

            return_object = registry_records
            httpcode = 200
        elif method == "PUT":
            registrydata = bodycontent
            validate = params.get("validate", True)

            registry_record = db_registries.get(registry, userId, session=dbsession)
            if not registry_record:
                httpcode = 404
                raise Exception("could not find existing registry to update")

            localconfig = anchore_engine.configuration.localconfig.get_config()
            if (
                registrydata["registry_user"] == "awsauto"
                or registrydata["registry_pass"] == "awsauto"
            ) and not localconfig["allow_awsecr_iam_auto"]:
                httpcode = 406
                raise Exception("'awsauto' is not enabled in service configuration")

            if validate:
                try:
                    registry_status = docker_registry.ping_docker_registry(registrydata)
                except Exception as err:
                    httpcode = 406
                    raise Exception(
                        "cannot ping supplied registry with supplied credentials - exception: {}".format(
                            str(err)
                        )
                    )

            rc = db_registries.update(registry, userId, registrydata, session=dbsession)
            registry_records = db_registries.get(registry, userId, session=dbsession)
            try:
                refresh_registry_creds(registry_records, dbsession)
            except Exception as err:
                logger.warn(
                    "failed to refresh registry credentials - exception: " + str(err)
                )

            return_object = registry_records
            httpcode = 200
        elif method == "DELETE":
            if not registry:
                raise Exception("no registryId passed in to delete")

            httpcode = 200
            return_object = True

            registry_records = db_registries.get(registry, userId, session=dbsession)
            for registry_record in registry_records:
                rc, httpcode = do_registry_delete(
                    userId, registry_record, dbsession, force=True
                )
                if httpcode not in list(range(200, 299)):
                    raise Exception(str(rc))

    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def system_subscriptions(dbsession, request_inputs):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    try:
        return_object = anchore_engine.common.subscription_types
        httpcode = 200
    except Exception as err:
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


################################################################################


def perform_vulnerability_scan(
    userId, imageDigest, dbsession, scantag=None, force_refresh=False, is_current=False
):
    # prepare inputs
    obj_store = None
    try:
        obj_store = anchore_engine.subsys.object_store.manager.get_manager()

        localconfig = anchore_engine.configuration.localconfig.get_config()
        verify = localconfig["internal_ssl_verify"]
        image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)

        annotations = {}
        try:
            if image_record.get("annotations", "{}"):
                annotations = json.loads(image_record.get("annotations", "{}"))
        except Exception as err:
            logger.warn(
                "could not marshal annotations from json - exception: " + str(err)
            )

        if not scantag:
            raise Exception("must supply a scantag")
    except Exception as err:
        raise Exception(
            "could not gather/prepare all necessary inputs for vulnerability - exception: "
            + str(err)
        )

    client = internal_client_for(PolicyEngineClient, userId)

    imageIds = []
    for image_detail in image_record["image_detail"]:
        imageId = image_detail["imageId"]
        if imageId and imageId not in imageIds:
            imageIds.append(imageId)

    archiveId = "{}/{}".format(image_record["imageDigest"], scantag)
    compare_archiveId = archiveId
    # if the call was made indicating that this scan is against the latest digest/tag mapping, then compare the result to the tag-only last result
    if is_current:
        compare_archiveId = scantag

    logger.debug(
        "archiveId={} compare_archiveId={}".format(archiveId, compare_archiveId)
    )

    for imageId in imageIds:
        # do the image load, just in case it was missed in analyze...
        try:
            resp = policy_engine_image_load(client, userId, imageId, imageDigest)
        except Exception as err:
            logger.warn("failed to load image data into policy engine: " + str(err))

        curr_vuln_result = client.get_image_vulnerabilities(
            user_id=userId, image_id=imageId, force_refresh=force_refresh
        )

        last_vuln_result = {}
        try:
            last_vuln_result = obj_store.get_document(
                userId, "vulnerability_scan", compare_archiveId
            )
        except:
            pass

        # compare them
        doqueue = False

        vdiff = {}
        if last_vuln_result and curr_vuln_result:
            vdiff = utils.diff_image_vulnerabilities(
                old_result=last_vuln_result,
                new_result=curr_vuln_result,
            )

        obj_store.put_document(
            userId, "vulnerability_scan", archiveId, curr_vuln_result
        )
        if archiveId != compare_archiveId:
            obj_store.put_document(
                userId, "vulnerability_scan", compare_archiveId, curr_vuln_result
            )

        try:
            if vdiff and (vdiff["updated"] or vdiff["added"] or vdiff["removed"]):
                logger.debug(
                    "detected difference in vulnerability results (current vs last)"
                )
                doqueue = True
            else:
                logger.debug("no difference in vulnerability scan")
        except Exception as err:
            logger.warn(
                "unable to interpret vulnerability difference data - exception: "
                + str(err)
            )

        # if different, set up a policy eval notification update
        if doqueue:
            try:
                logger.debug("queueing vulnerability update notification")
                npayload = {
                    "diff_vulnerability_result": vdiff,
                    "imageDigest": imageDigest,
                    "subscription_type": "vuln_update",
                }

                if annotations:
                    npayload["annotations"] = annotations

                success_event = anchore_engine.subsys.events.TagVulnerabilityUpdated(
                    user_id=userId, full_tag=scantag, data=npayload
                )
                try:
                    add_event(success_event, dbsession)
                except:
                    logger.warn(
                        "Ignoring error creating image vulnerability update event"
                    )
            except Exception as err:
                logger.warn("failed to enqueue notification - exception: " + str(err))

    return True


def perform_policy_evaluation(
    userId,
    imageDigest,
    dbsession,
    evaltag=None,
    policyId=None,
    interactive=False,
    newest_only=False,
):
    ret = {}
    # prepare inputs
    obj_store = None

    try:
        obj_store = anchore_engine.subsys.object_store.manager.get_manager()
        image_record = db_catalog_image.get(imageDigest, userId, session=dbsession)

        annotations = {}
        try:
            if image_record.get("annotations", "{}"):
                annotations = json.loads(image_record.get("annotations", "{}"))
        except Exception as err:
            logger.warn(
                "could not marshal annotations from json - exception: " + str(err)
            )

        if not policyId:
            policy_record = db_policybundle.get_active_policy(userId, session=dbsession)
            if not policy_record:
                raise Exception("no policy bundle is currently active")

            policyId = policy_record["policyId"]

        policy_bundle = obj_store.get_document(userId, "policy_bundles", policyId)

        if not evaltag:
            raise Exception("must supply an evaltag")

    except Exception as err:
        raise Exception(
            "could not gather/prepare all necessary inputs for policy evaluation - exception: "
            + str(err)
        )

    client = internal_client_for(PolicyEngineClient, userId)

    imageId = None
    for image_detail in image_record["image_detail"]:
        try:
            imageId = image_detail["imageId"]
            break
        except:
            pass

    # do the image load, just in case it was missed in analyze...
    try:
        logger.debug(
            "Reloading image: {}, user: {} digest: {}".format(
                imageId, userId, imageDigest
            )
        )
        resp = policy_engine_image_load(client, userId, imageId, imageDigest)
    except Exception as err:
        logger.warn("failed to load image data into policy engine: " + str(err))

    tagset = [evaltag]
    for fulltag in tagset:
        logger.debug(
            "calling policy_engine: "
            + str(userId)
            + " : "
            + str(imageId)
            + " : "
            + str(fulltag)
        )

        try:
            curr_evaluation_result = client.check_user_image_inline(
                user_id=userId,
                image_id=imageId,
                tag=fulltag,
                policy_bundle=policy_bundle,
            )
        except Exception as err:
            raise err
        curr_final_action = curr_evaluation_result.get("final_action", "").upper()
        # TODO hack! Include image digest and status, needed for the downstream notifications handler
        if curr_evaluation_result:
            curr_evaluation_result["image_digest"] = imageDigest
            if curr_final_action in ["GO", "WARN"]:
                curr_evaluation_result["status"] = "pass"
            else:
                curr_evaluation_result["status"] = "fail"

        # set up the newest evaluation
        evalId = hashlib.md5(
            ":".join(
                [policyId, userId, imageDigest, fulltag, str(curr_final_action)]
            ).encode("utf8")
        ).hexdigest()
        curr_evaluation_record = anchore_engine.common.helpers.make_eval_record(
            userId,
            evalId,
            policyId,
            imageDigest,
            fulltag,
            curr_final_action,
            "policy_evaluations/" + evalId,
        )

        if interactive:
            logger.debug(
                "interactive eval requested, skipping eval archive store and notification check"
            )
        else:
            # store the newest evaluation
            logger.debug(
                "non-interactive eval requested, performing eval archive store"
            )

            # get last image evaluation
            last_evaluation_record = db_policyeval.tsget_latest(
                userId, imageDigest, fulltag, session=dbsession
            )
            last_evaluation_result = {}
            last_final_action = None
            if last_evaluation_record:
                try:
                    last_evaluation_result = obj_store.get_document(
                        userId, "policy_evaluations", last_evaluation_record["evalId"]
                    )
                    last_final_action = last_evaluation_result["final_action"].upper()
                    # TODO hack! Include image digest and status, needed for the downstream notifications handler
                    last_evaluation_result["image_digest"] = imageDigest
                    if last_final_action in ["GO", "WARN"]:
                        last_evaluation_result["status"] = "pass"
                    else:
                        last_evaluation_result["status"] = "fail"
                except:
                    logger.warn("no last eval record - skipping")

            obj_store.put_document(
                userId, "policy_evaluations", evalId, curr_evaluation_result
            )
            db_policyeval.tsadd(
                policyId,
                userId,
                imageDigest,
                fulltag,
                curr_final_action,
                curr_evaluation_record,
                session=dbsession,
            )

            # compare last with newest evaluation
            doqueue = False
            if last_evaluation_result and curr_evaluation_result:
                if last_final_action != curr_final_action:
                    logger.debug(
                        "detected difference in policy eval results (current vs last)"
                    )
                    doqueue = True
                else:
                    logger.debug("no difference in policy evaluation")

            # if different, set up a policy eval notification update
            if doqueue:
                try:
                    logger.debug("queueing policy eval notification")
                    # Note: if this schema is changed, it should be updated in Swagger
                    npayload = {
                        "last_eval": last_evaluation_result,
                        "curr_eval": curr_evaluation_result,
                        "subscription_type": "policy_eval",
                    }
                    if annotations:
                        npayload["annotations"] = annotations

                    # new method
                    npayload["subscription_type"] = "policy_eval"
                    success_event = (
                        anchore_engine.subsys.events.TagPolicyEvaluationUpdated(
                            user_id=userId, full_tag=fulltag, data=npayload
                        )
                    )
                    try:
                        add_event(success_event, dbsession)
                    except:
                        logger.warn(
                            "Ignoring error creating image policy evaluation update event"
                        )
                except Exception as err:
                    logger.warn(
                        "failed to enqueue notification - exception: " + str(err)
                    )

        # done

    return curr_evaluation_record, curr_evaluation_result


ImageKey = collections.namedtuple("ImageKey", ["tag", "digest"])


def get_input_string(image_key: ImageKey) -> str:
    if image_key.digest:
        if image_key.digest == "unknown":
            return image_key.tag
        else:
            return "{}@{}".format(image_key.tag.split(":")[0], image_key.digest)
    else:
        return image_key.tag


def add_or_update_image_by_key(account_id: str, image_key: ImageKey, dbsession):
    input_string = get_input_string(image_key)
    registry_creds = get_and_refresh_registry_creds(account_id, dbsession)
    image_info = resolve_final_image_info(
        account_id, input_string, registry_creds, dbsession, {"fulltag": image_key.tag}
    )

    validate_image_size(image_info)
    add_or_update_image(
        dbsession,
        account_id,
        image_info["imageId"],
        tags=[image_info["fulltag"]],
        digests=[image_info["fulldigest"]],
        parentdigest=image_info.get("parentdigest", None),
        created_at=image_info.get("created_at_override", None),
        manifest=json.dumps(image_info["manifest"]),
        parent_manifest=json.dumps(image_info.get("parentmanifest", {})),
    )


def add_or_update_image(
    dbsession,
    userId,
    imageId,
    tags=[],
    digests=[],
    parentdigest=None,
    created_at=None,
    anchore_data=None,
    dockerfile=None,
    dockerfile_mode=None,
    manifest=None,
    annotations={},
    parent_manifest=None,
):
    ret = []
    logger.debug(
        "adding based on input tags/digests for imageId ("
        + str(imageId)
        + ") tags="
        + str(tags)
        + " digests="
        + str(digests)
    )
    obj_store = anchore_engine.subsys.object_store.manager.get_manager()

    image_ids = {}
    for d in digests:
        image_info = parse_dockerimage_string(d)
        registry = image_info["registry"]
        repo = image_info["repo"]
        digest = image_info["digest"]
        if not parentdigest:
            parentdigest = digest

        if registry not in image_ids:
            image_ids[registry] = {}
        if repo not in image_ids[registry]:
            image_ids[registry][repo] = {"digests": [], "tags": [], "imageId": imageId}
        if digest not in image_ids[registry][repo]["digests"]:
            image_ids[registry][repo]["digests"].append(digest)

    for d in tags:
        image_info = parse_dockerimage_string(d)
        registry = image_info["registry"]
        repo = image_info["repo"]
        digest = image_info["tag"]

        if registry not in image_ids:
            image_ids[registry] = {}
        if repo not in image_ids[registry]:
            image_ids[registry][repo] = {"digests": [], "tags": [], "imageId": imageId}
        if digest not in image_ids[registry][repo]["tags"]:
            image_ids[registry][repo]["tags"].append(digest)

    if not dockerfile and anchore_data:
        a = anchore_data[0]
        try:
            dockerfile = base64.b64encode(
                a["image"]["imagedata"]["image_report"]["dockerfile_contents"]
            )
            # dockerfile = a['image']['imagedata']['image_report']['dockerfile_contents'].encode('base64')
            dockerfile_mode = a["image"]["imagedata"]["image_report"]["dockerfile_mode"]
        except Exception as err:
            logger.warn(
                "could not extract dockerfile_contents from input anchore_data - exception: "
                + str(err)
            )
            dockerfile = None
            dockerfile_mode = None

    # logger.debug("rationalized input for imageId ("+str(imageId)+"): " + json.dumps(image_ids, indent=4))
    addlist = {}
    for registry in list(image_ids.keys()):
        for repo in list(image_ids[registry].keys()):
            imageId = image_ids[registry][repo]["imageId"]
            digests = image_ids[registry][repo]["digests"]
            tags = image_ids[registry][repo]["tags"]
            for d in digests:
                fulldigest = registry + "/" + repo + "@" + d
                for t in tags:
                    fulltag = registry + "/" + repo + ":" + t
                    new_image_record = anchore_engine.common.images.make_image_record(
                        userId,
                        "docker",
                        None,
                        image_metadata={
                            "tag": fulltag,
                            "digest": fulldigest,
                            "imageId": imageId,
                            "parentdigest": parentdigest,
                            "created_at": created_at,
                            "dockerfile": dockerfile,
                            "dockerfile_mode": dockerfile_mode,
                            "annotations": annotations,
                        },
                        registry_lookup=False,
                        registry_creds=(None, None),
                    )
                    imageDigest = new_image_record["imageDigest"]
                    image_record = db_catalog_image.get(
                        imageDigest, userId, session=dbsession
                    )
                    if not image_record:
                        # Create a new iamge
                        new_image_record["image_status"] = taskstate.init_state(
                            "image_status", None
                        )

                        if anchore_data:
                            rc = obj_store.put_document(
                                userId, "analysis_data", imageDigest, anchore_data
                            )

                            image_content_data = {}
                            localconfig = (
                                anchore_engine.configuration.localconfig.get_config()
                            )
                            all_content_types = localconfig.get(
                                "image_content_types", []
                            ) + localconfig.get("image_metadata_types", [])
                            for content_type in all_content_types:
                                try:
                                    image_content_data[
                                        content_type
                                    ] = anchore_engine.common.helpers.extract_analyzer_content(
                                        anchore_data, content_type, manifest=manifest
                                    )
                                except:
                                    image_content_data[content_type] = {}
                            if image_content_data:
                                logger.debug("adding image content data to archive")
                                rc = obj_store.put_document(
                                    userId,
                                    "image_content_data",
                                    imageDigest,
                                    image_content_data,
                                )

                            try:
                                logger.debug(
                                    "adding image analysis data to image_record"
                                )
                                anchore_engine.common.helpers.update_image_record_with_analysis_data(
                                    new_image_record, anchore_data
                                )
                            except Exception as err:
                                logger.warn(
                                    "unable to update image record with analysis data - exception: "
                                    + str(err)
                                )

                            new_image_record[
                                "analysis_status"
                            ] = taskstate.complete_state("analyze")
                        else:
                            new_image_record["analysis_status"] = taskstate.init_state(
                                "analyze", None
                            )

                        try:
                            rc = obj_store.put_document(
                                userId, "manifest_data", imageDigest, manifest
                            )
                            rc = obj_store.put_document(
                                userId,
                                "parent_manifest_data",
                                imageDigest,
                                parent_manifest,
                            )

                            rc = db_catalog_image.add_record(
                                new_image_record, session=dbsession
                            )
                            image_record = db_catalog_image.get(
                                imageDigest, userId, session=dbsession
                            )
                            if not manifest:
                                manifest = json.dumps({})
                            if not parent_manifest:
                                parent_manifest = json.dumps({})

                        except Exception as err:
                            raise anchore_engine.common.helpers.make_anchore_exception(
                                err,
                                input_message="cannot add image, failed to update archive/DB",
                                input_httpcode=500,
                            )

                    else:
                        # Update existing image record
                        new_image_detail = anchore_engine.common.images.clean_docker_image_details_for_update(
                            new_image_record["image_detail"]
                        )

                        if (
                            "imageId" not in new_image_detail
                            or not new_image_detail["imageId"]
                        ):
                            for image_detail in image_record["image_detail"]:
                                if (
                                    "imageId" in image_detail
                                    and image_detail["imageId"]
                                ):
                                    for new_id in new_image_detail:
                                        new_id["imageId"] = image_detail["imageId"]
                                    break

                        if dockerfile:
                            for new_id in new_image_detail:
                                new_id["dockerfile"] = dockerfile

                        if dockerfile_mode:
                            image_record["dockerfile_mode"] = dockerfile_mode

                        if annotations:
                            if image_record["annotations"]:
                                try:
                                    annotation_data = json.loads(
                                        image_record["annotations"]
                                    )
                                except Exception as err:
                                    logger.warn(
                                        "could not marshal annotations into json - exception: "
                                        + str(err)
                                    )
                                    annotation_data = {}
                            else:
                                annotation_data = {}

                            try:
                                annotation_data.update(annotations)
                                final_annotation_data = {}
                                for k, v in list(annotation_data.items()):
                                    if v != "null":
                                        final_annotation_data[k] = v
                                image_record["annotations"] = json.dumps(
                                    final_annotation_data
                                )
                            except Exception as err:
                                logger.debug(
                                    "could not prepare annotations for store - exception: "
                                    + str(err)
                                )

                        try:
                            rc = obj_store.put_document(
                                userId, "manifest_data", imageDigest, manifest
                            )
                            rc = obj_store.put_document(
                                userId,
                                "parent_manifest_data",
                                imageDigest,
                                parent_manifest,
                            )

                            rc = db_catalog_image.update_record_image_detail(
                                image_record, new_image_detail, session=dbsession
                            )

                            # TODO - update policy engine

                            image_record = db_catalog_image.get(
                                imageDigest, userId, session=dbsession
                            )
                            if not manifest:
                                manifest = json.dumps({})
                            if not parent_manifest:
                                parent_manifest = json.dumps({})
                        except Exception as err:
                            raise anchore_engine.common.helpers.make_anchore_exception(
                                err,
                                input_message="cannot add image, failed to update archive/DB",
                                input_httpcode=500,
                            )

                    addlist[imageDigest] = image_record

    for imageDigest in list(addlist.keys()):
        ret.append(addlist[imageDigest])

    return ret


def _image_deletion_checks_and_prep(userId, image_record, dbsession, force=False):

    dodelete = False
    msgdelete = "could not make it though delete checks"
    image_ids = []
    image_fulltags = []

    # do some checking before delete
    try:
        # check one - don't delete anything that is being analyzed
        if image_record["analysis_status"] == taskstate.working_state("analyze"):
            if not force:
                raise Exception("cannot delete image that is being analyzed")

        # check two - don't delete anything that is the latest of any of its tags, and has an active subscription
        for image_detail in image_record["image_detail"]:
            fulltag = (
                image_detail["registry"]
                + "/"
                + image_detail["repo"]
                + ":"
                + image_detail["tag"]
            )
            image_fulltags.append(fulltag)

            if "imageId" in image_detail and image_detail["imageId"]:
                image_ids.append(image_detail["imageId"])

            dbfilter = {}
            dbfilter["registry"] = image_detail["registry"]
            dbfilter["repo"] = image_detail["repo"]
            dbfilter["tag"] = image_detail["tag"]

            latest_image_records = db_catalog_image.get_byimagefilter(
                userId, "docker", dbfilter=dbfilter, onlylatest=True, session=dbsession
            )
            for latest_image_record in latest_image_records:
                if latest_image_record["imageDigest"] == image_record["imageDigest"]:
                    dbfilter = {}
                    dbfilter["subscription_key"] = fulltag
                    subscription_records = db_subscriptions.get_byfilter(
                        userId, session=dbsession, **dbfilter
                    )
                    for subscription_record in subscription_records:
                        if subscription_record["active"]:
                            if not force:
                                raise Exception(
                                    "cannot delete image that is the latest of its tags, and has active subscription"
                                )
                            else:
                                subscription_record["active"] = False
                                db_subscriptions.upsert(
                                    userId,
                                    subscription_record["subscription_key"],
                                    subscription_record["subscription_type"],
                                    subscription_record,
                                    session=dbsession,
                                )

        # checked out - do the delete
        dodelete = True

    except Exception as err:
        msgdelete = str(err)
        dodelete = False

    return dodelete, msgdelete, image_ids, image_fulltags


def _delete_image_artifacts(account_id, image_digest, image_ids, full_tags, db_session):
    error = None
    rcs = []
    obj_store = anchore_engine.subsys.object_store.manager.get_manager()
    # digest-based archiveId buckets
    for bucket in [
        "analysis_data",
        "query_data",
        "image_content_data",
        "image_summary_data",
        "manifest_data",
        "parent_manifest_data",
    ]:
        # try-except block ensures an attempt to delete every artifact despite errors
        try:
            logger.debug("DELETEing image from archive %s/%s", bucket, image_digest)
            rc = obj_store.delete(account_id, bucket, image_digest)
            rcs.append(rc)
        except Exception as e:
            error = e
            logger.exception(
                "Error deleting image from archive %s/%s", bucket, image_digest
            )

    # digest/tag-based archiveId buckets
    for bucket in ["vulnerability_scan"]:
        for full_tag in full_tags:
            archive_id = "{}/{}".format(image_digest, full_tag)
            # try-except block ensures an attempt to delete every artifact despite errors
            try:
                logger.debug("DELETEing image from archive %s/%s", bucket, archive_id)
                rc = obj_store.delete(account_id, bucket, archive_id)
                rcs.append(rc)
            except Exception as e:
                error = e
                logger.exception(
                    "Error deleting image from archive %s/%s", bucket, archive_id
                )

    if error:
        raise error
    else:
        return rcs


def _delete_image_catalog(account_id, image_digest, image_ids, full_tags, db_session):
    logger.debug("DELETEing image from catalog")
    rc = db_catalog_image.delete(image_digest, account_id, session=db_session)

    return rc


def _delete_image_policy_engine(
    account_id, image_digest, image_ids, full_tags, db_session
):
    error = None
    rcs = []
    pe_client = internal_client_for(PolicyEngineClient, userId=account_id)

    for img_id in set(image_ids):
        # try-except block ensures an attempt to delete every image id despite errors
        try:
            logger.debug(
                "DELETING image from policy engine account_id=%s image_id=%s",
                account_id,
                img_id,
            )
            rc = pe_client.delete_image(user_id=account_id, image_id=img_id)
            rcs.append(rc)
        except Exception as e:
            error = e
            logger.exception(
                "Error deleting image id %s from policy engine", image_digest
            )

    if error:
        raise error
    else:
        return rcs


# collection of description and delete function tuples. Each delete that take account_id, image_digest, image_ids, full_tags and db_session as arguments
# TODO hack to support extensions, come up with a better (oo) solution to override and extend behaviour
image_gc_functions = [
    ("artifacts", _delete_image_artifacts),
    ("catalog record", _delete_image_catalog),
    ("policy-engine record", _delete_image_policy_engine),
]


def _delete_image_for_real(userId, image_record, dbsession, image_ids, image_fulltags):
    image_digest = image_record["imageDigest"]
    logger.debug(
        "Begin image deletion for account_id=%s, digest=%s, tags=%s, ids=%s",
        userId,
        image_digest,
        image_fulltags,
        image_ids,
    )
    for desc, delete_func in image_gc_functions:
        try:
            logger.debug("Executing delete for image %s", desc)
            delete_func(
                account_id=userId,
                image_digest=image_digest,
                image_ids=image_ids,
                full_tags=image_fulltags,
                db_session=dbsession,
            )
        except Exception:
            # swallow the error for now and continue with the image clean up
            logger.exception("Error executing image %s", desc)


def _queue_image_for_deletion(account_id, digest, db_session, force=False):
    try:
        image_record = db_catalog_image.get(digest, account_id, db_session)
        if image_record:
            if image_record.get("image_status", None) == taskstate.queued_state(
                "image_status"
            ):  # image already queued for deletion, nothing to do here
                return_object = DeleteImageResponse(
                    digest, taskstate.queued_state("image_status"), None
                )
            else:
                (
                    can_delete,
                    message,
                    image_ids,
                    image_fulltags,
                ) = _image_deletion_checks_and_prep(
                    account_id, image_record, db_session, force
                )
                if can_delete:  # queue the image for deletion
                    db_catalog_image.update_image_status(
                        account_id,
                        digest,
                        taskstate.queued_state("image_status"),
                        session=db_session,
                    )
                    return_object = DeleteImageResponse(
                        digest, taskstate.queued_state("image_status"), None
                    )
                else:
                    return_object = DeleteImageResponse(
                        digest, "delete_failed", message
                    )
        else:
            return_object = DeleteImageResponse(
                digest, "not_found", "No image found with the digest"
            )

        httpcode = 200
    except Exception as e:
        return_object = DeleteImageResponse(digest, "delete_failed", str(e))
        httpcode = 500

    return return_object._asdict(), httpcode


def delete_images_async(account_id, db_session, image_digests, force=False):
    return_object = []
    httpcode = 500

    try:
        for digest in image_digests:
            ret = None
            try:
                ret, _ = _queue_image_for_deletion(
                    account_id, digest, db_session, force
                )
            finally:
                if ret:
                    return_object.append(ret)

        httpcode = 200
    except Exception as err:
        httpcode = 500
        return_object = anchore_engine.common.helpers.make_response_error(
            err, in_httpcode=httpcode
        )

    return return_object, httpcode


def do_image_delete(userId, image_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        if True:
            (
                dodelete,
                msgdelete,
                image_ids,
                image_fulltags,
            ) = _image_deletion_checks_and_prep(userId, image_record, dbsession, force)

        if dodelete:
            _delete_image_for_real(
                userId, image_record, dbsession, image_ids, image_fulltags
            )

            return_object = True
            httpcode = 200
        else:
            httpcode = 409
            raise Exception(msgdelete)
    except Exception as err:
        logger.warn("DELETE failed - exception: " + str(err))
        return_object = str(err)

    return return_object, httpcode


def do_subscription_delete(userId, subscription_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        dbfilter = {"subscription_id": subscription_record["subscription_id"]}
        rc = db_subscriptions.delete_byfilter(
            userId, remove=True, session=dbsession, **dbfilter
        )
        if not rc:
            raise Exception("DB delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


def do_policy_delete(
    userId, policy_record, dbsession, cleanup_evals=False, force=False
):
    return_object = False
    httpcode = 500

    try:
        policyId = policy_record["policyId"]

        rc = db_policybundle.delete(policyId, userId, session=dbsession)
        if not rc:
            httpcode = 500
            raise Exception("DB delete of policyId (" + str(policyId) + ") failed")
        else:
            if cleanup_evals:
                dbfilter = {"policyId": policyId}
                eval_records = db_policyeval.tsget_byfilter(
                    userId, session=dbsession, **dbfilter
                )
                for eval_record in eval_records:
                    db_policyeval.delete_record(eval_record, session=dbsession)

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


def do_evaluation_delete(userId, eval_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        rc = db_policyeval.delete_record(eval_record, session=dbsession)
        if not rc:
            raise Exception("DB update failed")

        httpcode = 200
        return_object = True
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


def do_archive_delete(userId, archive_document, session, force=False):
    return_object = False
    httpcode = 500

    try:
        obj_store = anchore_engine.subsys.object_store.manager.get_manager()
        rc = obj_store.delete(
            userId, archive_document["bucket"], archive_document["archiveId"]
        )
        if not rc:
            raise Exception("archive delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


def do_registry_delete(userId, registry_record, dbsession, force=False):
    return_object = False
    httpcode = 500

    try:
        registryId = registry_record["registry"]
        rc = db_registries.delete(registryId, userId, session=dbsession)
        if not rc:
            raise Exception("DB delete failed")

        return_object = True
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return return_object, httpcode


def add_event(event, dbsession, quiet=True):
    """
    Add an event object

    Returns a dict object of the event as was added to the system

    :param event:
    :param dbsession:
    :param quiet:
    :return:
    """

    if dbsession is None:
        # Create a new session for this with its own transaction
        with session_scope() as session:
            return add_event_json(event.to_dict(), session, quiet)
    else:
        return add_event_json(event.to_dict(), dbsession, quiet)


def isolated_add_event(event, quiet=True):
    """
    Add an event object, but in its own transaction, not bound to an existing transaction scope

    Returns a dict object of the event as was added to the system

    :param event: event object
    :param quiet: boolean indicating if false then exceptions on event add should be swallowed to prevent blocking the caller. If false, exceptions are raised
    :return:
    """
    with session_scope() as session:
        return add_event_json(event.to_dict(), session, quiet)


def add_event_json(event_json, dbsession, quiet=True):
    """
    Add a raw json dict as an event
    :param event_json:
    :param dbsession:
    :param quiet:
    :return:
    """

    try:
        added_event_json = db_events.add(event_json, session=dbsession)

        logger.debug(
            "queueing event creation notification: {}".format(added_event_json)
        )
        rc = notifications.queue_notification(
            added_event_json["event"]["resource"]["user_id"],
            subscription_key=added_event_json["event"]["level"],
            subscription_type="event_log",
            payload=added_event_json,
        )
        return added_event_json
    except:
        if quiet:
            logger.exception(
                "Ignoring error creating/notifying event: {}".format(event_json)
            )
        else:
            raise


def list_evals_impl(
    dbsession,
    userId,
    policyId=None,
    imageDigest=None,
    tag=None,
    evalId=None,
    newest_only=False,
    interactive=False,
):
    logger.debug("looking up eval record: " + userId)

    object_store_mgr = object_store.get_manager()

    # set up the filter based on input
    dbfilter = {}
    latest_eval_record = latest_eval_result = None

    if policyId is not None:
        dbfilter["policyId"] = policyId

    if imageDigest is not None:
        dbfilter["imageDigest"] = imageDigest

    if tag is not None:
        dbfilter["tag"] = tag

    if evalId is not None:
        dbfilter["evalId"] = evalId

    # perform an interactive eval to get/install the latest
    try:
        logger.debug("performing eval refresh: " + str(dbfilter))
        imageDigest = dbfilter["imageDigest"]
        if "tag" in dbfilter:
            evaltag = dbfilter["tag"]
        else:
            evaltag = None

        if "policyId" in dbfilter:
            policyId = dbfilter["policyId"]
        else:
            policyId = None

        latest_eval_record, latest_eval_result = perform_policy_evaluation(
            userId,
            imageDigest,
            dbsession,
            evaltag=evaltag,
            policyId=policyId,
            interactive=interactive,
            newest_only=newest_only,
        )
    except Exception as err:
        logger.error("interactive eval failed - exception: {}".format(err))

    records = []
    if interactive or newest_only:
        try:
            latest_eval_record["result"] = latest_eval_result
            records = [latest_eval_record]
        except:
            raise Exception(
                "interactive or newest_only eval requested, but unable to perform eval at this time"
            )
    else:
        records = db_policyeval.tsget_byfilter(userId, session=dbsession, **dbfilter)
        for record in records:
            try:
                result = object_store_mgr.get_document(
                    userId, "policy_evaluations", record["evalId"]
                )
                record["result"] = result
            except:
                record["result"] = {}

    return records


def delete_evals_impl(
    dbsession, userId, policyId=None, imageDigest=None, tag=None, evalId=None
):
    # set up the filter based on input
    dbfilter = {}

    if policyId is not None:
        dbfilter["policyId"] = policyId

    if imageDigest is not None:
        dbfilter["imageDigest"] = imageDigest

    if tag is not None:
        dbfilter["tag"] = tag

    if evalId is not None:
        dbfilter["evalId"] = evalId

    logger.debug("looking up eval record: " + userId)

    if not dbfilter:
        raise Exception("not enough detail in body to find records to delete")

    rc = db_policyeval.delete_byfilter(userId, session=dbsession, **dbfilter)
    if not rc:
        raise Exception("DB delete failed")
    else:
        return True


def upsert_eval(dbsession, userId, record):
    rc = db_policyeval.tsadd(
        record["policyId"],
        userId,
        record["imageDigest"],
        record["tag"],
        record["final_action"],
        {"policyeval": record["policyeval"], "evalId": record["evalId"]},
        session=dbsession,
    )
    if not rc:
        raise Exception("DB update failed")
    else:
        return record


################################################################################

# return true or false if image is a valid size based upon max_compressed_image_size_mb specified in config
def is_image_valid_size(image_info):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    max_compressed_image_size_mb = localconfig.get("max_compressed_image_size_mb", -1)
    compressed_image_size = image_info.get("compressed_size")

    if (
        max_compressed_image_size_mb
        and max_compressed_image_size_mb > -1
        and compressed_image_size
        and anchore_utils.bytes_to_mb(compressed_image_size, round_to=2)
        > max_compressed_image_size_mb
    ):
        return False
    else:
        return True
