"""
API controller for /archives routes

"""
import json
import uuid

from sqlalchemy import or_

from anchore_engine import db
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.apis.exceptions import BadRequest
from anchore_engine.common.helpers import make_response_error
from anchore_engine.db import (
    session_scope,
    ArchivedImage,
    ArchivedImageDocker,
    db_archived_images,
    ArchiveTransitionRule,
    ArchiveTransitionHistoryEntry,
    ArchiveTransitions,
)
from anchore_engine.services.catalog.archiver import (
    ArchiveImageTask,
    DeleteArchivedImageTask,
)
from anchore_engine.subsys import logger
from anchore_engine.subsys.metrics import flask_metrics
from anchore_engine.utils import epoch_to_rfc3339

authorizer = get_authorizer()


def archived_img_to_msg(obj: ArchivedImage):
    return {
        "imageDigest": obj.imageDigest,
        "parentDigest": obj.parentDigest,
        "annotations": json.loads(obj.annotations) if obj.annotations else {},
        "status": obj.status,
        "analyzed_at": epoch_to_rfc3339(obj.analyzed_at),
        "archive_size_bytes": obj.archive_size_bytes,
        "image_detail": [archive_img_docker_to_msg(x) for x in obj.tags()],
        "created_at": epoch_to_rfc3339(obj.created_at),
        "last_updated": epoch_to_rfc3339(obj.last_updated),
    }


def archive_img_docker_to_msg(obj: ArchivedImageDocker):
    return {
        "pullstring": obj.registry + "/" + obj.repository + ":" + obj.tag,
        "registry": obj.registry,
        "repository": obj.repository,
        "tag": obj.tag,
        "detected_at": epoch_to_rfc3339(obj.tag_detected_at),
        "created_at": epoch_to_rfc3339(obj.created_at),
        "last_updated": epoch_to_rfc3339(obj.last_updated),
    }


def transition_rule_db_to_json(db_rule: ArchiveTransitionRule):
    return {
        "rule_id": db_rule.rule_id,
        "selector": {
            "registry": db_rule.selector_registry,
            "repository": db_rule.selector_repository,
            "tag": db_rule.selector_tag,
        },
        "exclude": {
            "expiration_days": db_rule.exclude_expiration_days,
            "selector": {
                "registry": db_rule.exclude_selector_registry,
                "repository": db_rule.exclude_selector_repository,
                "tag": db_rule.exclude_selector_tag,
            },
        },
        "analysis_age_days": db_rule.analysis_age_days,
        "tag_versions_newer": db_rule.tag_versions_newer,
        "transition": db_rule.transition.value,
        "system_global": db_rule.system_global,
        "max_images_per_account": db_rule.max_images_per_account,
        "created_at": epoch_to_rfc3339(db_rule.created_at),
        "last_updated": epoch_to_rfc3339(db_rule.last_updated),
    }


def transition_history_to_json(history_rec: ArchiveTransitionHistoryEntry):
    return {
        "transition_task_id": history_rec.transition_task_id,
        "rule_id": history_rec.rule_id,
        "imageDigest": history_rec.digest,
        "transition": history_rec.transition.value,
        "state": history_rec.transition_state,
        "created_at": epoch_to_rfc3339(history_rec.created_at),
        "last_updated": epoch_to_rfc3339(history_rec.last_updated),
    }


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_archives():
    """
    GET /archives

    :return:
    """
    try:
        with session_scope() as session:
            imgs = db_archived_images.summarize(session) or []
            rules = (
                session.query(ArchiveTransitionRule)
                .filter_by(account=ApiRequestContextProxy.namespace())
                .all()
                or []
            )
            rule_count = len(rules)
            newest = None
            if rule_count > 0:
                newest = epoch_to_rfc3339(max(map(lambda x: x.last_updated, rules)))

        return {"images": imgs, "rules": {"count": rule_count, "last_updated": newest}}
    except Exception as ex:
        logger.exception("Failed to list archives")
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_image_analysis_archive():
    """
    GET /archives/images

    :return:
    """
    try:
        with session_scope() as session:
            response_obj = db_archived_images.summarize(session)
        return response_obj, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_analysis_archive_rules(system_global=True):
    """
    GET /archives/rules
    :return:
    """
    try:
        with session_scope() as session:
            if system_global:
                qry = session.query(ArchiveTransitionRule).filter(
                    or_(
                        ArchiveTransitionRule.account
                        == ApiRequestContextProxy.namespace(),
                        ArchiveTransitionRule.system_global == True,
                    )
                )
                return [transition_rule_db_to_json(x) for x in qry], 200
            else:
                return [
                    transition_rule_db_to_json(x)
                    for x in session.query(ArchiveTransitionRule).filter_by(
                        account=ApiRequestContextProxy.namespace()
                    )
                ], 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def create_analysis_archive_rule(rule):
    """
    POST /archives/rules

    :return:
    """

    try:
        with session_scope() as session:
            # Validate that only one system_global rule has max_images_per_account set
            qry = session.query(ArchiveTransitionRule).filter(
                ArchiveTransitionRule.account == ApiRequestContextProxy.namespace(),
                ArchiveTransitionRule.system_global == True,
                ArchiveTransitionRule.max_images_per_account != None,
            )
            if qry.first() is not None:
                raise BadRequest(
                    "A system_global Archive Transition Rule already exists with max_images_per_account set",
                    {"existingRule": repr(qry.first())},
                )

            r = ArchiveTransitionRule()
            r.account = ApiRequestContextProxy.namespace()
            r.rule_id = uuid.uuid4().hex
            r.selector_registry = rule.get("selector", {}).get("registry", "*")
            r.selector_repository = rule.get("selector", {}).get("repository", "*")
            r.selector_tag = rule.get("selector", {}).get("tag", "*")
            r.analysis_age_days = int(rule.get("analysis_age_days", -1))
            r.tag_versions_newer = int(rule.get("tag_versions_newer", -1))
            r.transition = ArchiveTransitions(rule.get("transition"))
            r.system_global = rule.get("system_global", False)

            # Transition Rule Exclude information (defaults to NOT exclude things), but will supercede the selector
            # above
            exclude = rule.get("exclude", {})
            exclude_selector = exclude.get("selector", {})
            r.exclude_selector_registry = exclude_selector.get("registry", "")
            r.exclude_selector_repository = exclude_selector.get("repository", "")
            r.exclude_selector_tag = exclude_selector.get("tag", "")
            r.exclude_expiration_days = exclude.get("expiration_days", -1)
            r.max_images_per_account = rule.get("max_images_per_account", None)

            session.add(r)
            session.flush()
            return transition_rule_db_to_json(r), 200

    except Exception as ex:
        logger.exception("Exception in add")
        return (
            make_response_error("Error adding rule: {}".format(ex), in_httpcode=500),
            500,
        )


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_analysis_archive_rule(rule_id):
    """
    GET /archives/rules/{rule_id}

    :param rule_id:
    :return:
    """
    try:
        with session_scope() as session:
            rule = (
                session.query(ArchiveTransitionRule)
                .filter_by(account=ApiRequestContextProxy.namespace(), rule_id=rule_id)
                .one_or_none()
            )
            if rule is None:
                # Allow users to get the system global rules
                rule = (
                    session.query(ArchiveTransitionRule)
                    .filter_by(rule_id=rule_id, system_global=True)
                    .one_or_none()
                )
                if rule is None:
                    return make_response_error("Rule not found", in_httpcode=404), 404

            return transition_rule_db_to_json(rule), 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_analysis_archive_rule(rule_id):
    """
    DELETE /archives/rule/{rule_id}
    :return:
    """
    try:
        with session_scope() as session:
            rule = (
                session.query(ArchiveTransitionRule)
                .filter_by(account=ApiRequestContextProxy.namespace(), rule_id=rule_id)
                .one_or_none()
            )
            if rule is not None:
                session.delete(rule)
            else:
                return make_response_error("Rule not found", in_httpcode=404), 404

        return None, 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_analysis_archive_rule_history(rule_id):
    """
    GET /archives/rule/{rule_id}/history

    :return:
    """
    try:
        with session_scope() as session:
            return [
                transition_history_to_json(x)
                for x in session.query(ArchiveTransitionHistoryEntry).filter_by(
                    account=ApiRequestContextProxy.namespace(), rule_id=rule_id
                )
            ], 200
    except Exception as ex:
        return make_response_error(ex, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_analysis_archive():
    """
    GET /archives/images

    """
    try:
        with db.session_scope() as session:
            return [
                archived_img_to_msg(img)
                for img in db_archived_images.list(
                    session, ApiRequestContextProxy.namespace()
                )
            ], 200

    except Exception as err:
        logger.exception("Error listing archived images.")
        return make_response_error(err, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def archive_image_analysis(imageReferences):
    """
    POST /archives/images

    body = [digest1, digest2, ... ]

    """

    try:
        if not imageReferences or len(imageReferences) > 100:
            return (
                make_response_error(
                    "Bad Request. Must include a list of digests between 1 and 100 entries long",
                    in_httpcode=400,
                ),
                400,
            )

        results = []

        for digest in imageReferences:
            try:
                # Do synchronous part to start the state transition
                task = ArchiveImageTask(
                    account=ApiRequestContextProxy.namespace(), image_digest=digest
                )
                result_status, result_detail = task.run()
                results.append(
                    {
                        "digest": task.image_digest,
                        "status": result_status,
                        "detail": result_detail,
                    }
                )
            except Exception as ex:
                logger.exception(
                    "Unexpected an uncaught exception from the archive task execution"
                )
                results.append({"digest": digest, "status": "error", "detail": str(ex)})

        return results, 200
    except Exception as err:
        logger.exception("Error processing image add")
        return make_response_error(err, in_httpcode=500), 500


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_archived_analysis(imageDigest):
    """
    GET /archives/images/{digest}

    :param imageDigest:
    :return:
    """

    try:
        with db.session_scope() as session:
            return_object = db_archived_images.get(
                session, ApiRequestContextProxy.namespace(), imageDigest
            )

            if not return_object:
                return make_response_error("Not found in archive", in_httpcode=404), 404

            return archived_img_to_msg(return_object), 200
    except Exception as err:
        logger.exception("Error listing archived images")
        return make_response_error(str(err), in_httpcode=500), 500


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_archived_analysis(imageDigest, force=False):
    """
    DELETE /archives/images/{digest}

    :param imageDigest: image digest to delete the archive for
    :return:
    """

    # # Read the archive manifest, and delete or restore the artifacts
    try:
        if force:
            start_statuses = ["archiving", "archived", "deleting", "deleted"]
        else:
            start_statuses = ["archived", "deleting"]

        with session_scope() as session:
            resp = db_archived_images.update_image_status(
                session,
                ApiRequestContextProxy.namespace(),
                imageDigest,
                start_statuses,
                "deleting",
            )

        if resp is None:
            return make_response_error("Not found in archive", in_httpcode=404), 404
    except Exception as ex:
        logger.exception(
            "Error deleting archive for image {}/{}".format(
                ApiRequestContextProxy.namespace(), imageDigest
            )
        )
        return (
            make_response_error("Invalid object state: {}".format(ex), in_httpcode=400),
            400,
        )

    try:
        task = DeleteArchivedImageTask(
            account=ApiRequestContextProxy.namespace(), image_digest=imageDigest
        )
        task.run()
        resp = None
        return resp, 200
    except Exception as ex:
        logger.exception("Failed deleting archived image")
        return (
            make_response_error(
                "Error deleting image archive: {}".format(ex), in_httpcode=500
            ),
            500,
        )


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def import_archive(imageDigest, archive_file):
    from anchore_engine.services.catalog import archiver

    try:
        digest = imageDigest
        task = archiver.RestoreArchivedImageTaskFromArchiveTarfile(
            account=ApiRequestContextProxy.namespace(),
            fileobj=archive_file,
            image_digest=digest,
        )
        task.start()
    except Exception as ex:
        logger.exception("Failed to import image archive")
        return (
            make_response_error(
                "Error importing image archive: {}".format(ex), in_httpcode=500
            ),
            500,
        )

    return "Success", 200
