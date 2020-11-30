from flask import jsonify

from anchore_engine.common.errors import AnchoreError
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED
from anchore_engine.apis.exceptions import (
    BadRequest,
    ConflictingRequest,
    ResourceNotFound,
    InternalError,
    AnchoreApiError,
)
from anchore_engine.clients.services.simplequeue import (
    LeaseAcquisitionFailedError,
    LeaseUnavailableError,
)
from anchore_engine.common.helpers import make_response_error
from anchore_engine.services.policy_engine.api.models import (
    FeedMetadata,
    FeedGroupMetadata,
)
from anchore_engine.services.policy_engine.engine.feeds import db, sync
from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask
from anchore_engine.subsys import logger as log
from anchore_engine.db import (
    FeedMetadata as DbFeedMetadata,
    FeedGroupMetadata as DbFeedGroupMetadata,
)
import typing

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_feeds(refresh_counts=False):
    """
    GET /feeds

    :param include_counts (ignored since counts are handled in the record now)
    :param refresh_counts: forcibly update the group counts (not normally necessary)
    :return:
    """

    if refresh_counts:
        sync.DataFeeds.update_counts()

    response = [x.to_json() for x in _marshall_feeds_response()]

    return jsonify(response)


def _marshall_feeds_response() -> typing.List[FeedMetadata]:
    response = []
    meta = db.get_all_feeds_detached()

    for feed in meta:
        response.append(_marshall_feed_response(feed))

    return response


def _marshall_feed_response(feed: DbFeedMetadata) -> FeedMetadata:
    if not feed:
        return ValueError(feed)

    i = FeedMetadata()
    i.name = feed.name
    i.last_full_sync = feed.last_full_sync
    i.created_at = feed.created_at
    i.updated_at = feed.last_update
    i.enabled = feed.enabled
    i.groups = []

    for group in feed.groups:
        i.groups.append(_marshall_group_response(group))

    return i


def _marshall_group_response(group: DbFeedGroupMetadata) -> FeedGroupMetadata:
    if not group:
        raise ValueError(group)

    g = FeedGroupMetadata()
    g.name = group.name
    g.last_sync = group.last_sync
    g.created_at = group.created_at
    g.updated_at = group.last_update
    g.enabled = group.enabled
    g.record_count = group.count
    return g


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def sync_feeds(sync=True, force_flush=False):
    """
    POST /feeds?sync=True&force_flush=True

    :param sync: Boolean. If true, do a sync. If false, don't sync.
    :param force_flush: Boolean. If true, remove all previous data and replace with data from upstream source
    :return:
    """

    result = []
    if sync:
        try:
            result = FeedsUpdateTask.run_feeds_update(force_flush=force_flush)
        except (LeaseAcquisitionFailedError, LeaseUnavailableError) as e:
            log.exception(
                "Could not acquire lock on feed sync, likely another sync already in progress"
            )
            return (
                make_response_error(
                    "Feed sync lock already held",
                    in_httpcode=409,
                    details={
                        "error_codes": [
                            AnchoreError.FEED_SYNC_ALREADY_IN_PROGRESS.name
                        ],
                        "message": AnchoreError.FEED_SYNC_ALREADY_IN_PROGRESS.value,
                    },
                ),
                409,
            )
        except Exception as e:
            log.exception("Error executing feed update task")
            return jsonify(make_response_error(e, in_httpcode=500)), 500

    return jsonify(result), 200


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def toggle_feed_enabled(feed, enabled):
    if type(enabled) != bool:
        raise BadRequest(message="state must be a boolean", detail={"value": enabled})

    session = db.get_session()
    try:
        f = db.set_feed_enabled(session, feed, enabled)
        if not f:
            raise ResourceNotFound(feed, detail={})
        session.flush()

        updated = _marshall_feed_response(f).to_json()
        session.commit()

        return jsonify(updated), 200
    except AnchoreApiError:
        session.rollback()
        raise
    except Exception as e:
        log.error("Could not update feed enabled status")
        session.rollback()
        return jsonify(make_response_error(e, in_httpcode=500)), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def toggle_group_enabled(feed, group, enabled):
    if type(enabled) != bool:
        raise BadRequest(message="state must be a boolean", detail={"value": enabled})

    session = db.get_session()
    try:
        g = db.set_feed_group_enabled(session, feed, group, enabled)
        if not g:
            raise ResourceNotFound(group, detail={})

        session.flush()

        grp = _marshall_group_response(g).to_json()
        session.commit()

        return jsonify(grp), 200
    except AnchoreApiError:
        session.rollback()
        raise
    except Exception:
        log.error("Could not update feed group enabled status")
        session.rollback()
        raise


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_feed(feed):
    session = db.get_session()
    try:
        f = db.lookup_feed(db_session=session, feed_name=feed)
        if not f:
            raise ResourceNotFound(resource=feed, detail={})
        elif f.enabled:
            raise ConflictingRequest(
                message="Cannot delete an enabled feed. Disable the feed first",
                detail={},
            )
    except AnchoreApiError:
        raise
    except Exception as e:
        return jsonify(make_response_error(e, in_httpcode=500)), 500
    finally:
        session.rollback()

    try:
        f = sync.DataFeeds.delete_feed(feed)
        if f:
            return jsonify(_marshall_feed_response(f).to_json()), 200
        else:
            raise ResourceNotFound(feed, detail={})
    except KeyError as e:
        raise ResourceNotFound(resource=str(e), detail={"feed": feed})
    except AnchoreApiError:
        raise
    except Exception as e:
        return jsonify(make_response_error(e, in_httpcode=500)), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_group(feed, group):
    session = db.get_session()
    try:
        f = db.lookup_feed_group(db_session=session, feed_name=feed, group_name=group)
        if not f:
            raise ResourceNotFound(group, detail={})
        elif f.enabled:
            raise ConflictingRequest(
                message="Cannot delete an enabled feed group. Disable the feed group first",
                detail={},
            )
    except AnchoreApiError:
        raise
    except Exception as e:
        return jsonify(make_response_error(e, in_httpcode=500)), 500
    finally:
        session.rollback()

    try:
        g = sync.DataFeeds.delete_feed_group(feed_name=feed, group_name=group)
        log.info("Flushed group records {}".format(g))
        if g:
            return jsonify(_marshall_group_response(g).to_json()), 200
        else:
            raise ResourceNotFound(group, detail={})
    except KeyError as e:
        raise ResourceNotFound(resource=str(e), detail={"feed": feed, "group": group})
    except AnchoreApiError:
        raise
    except Exception as e:
        log.error("Could not flush feed group {}/{}".format(feed, group))
        return jsonify(make_response_error(e, in_httpcode=500)), 500
