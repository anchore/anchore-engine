from dataclasses import asdict

from flask import jsonify

from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.exceptions import (
    AnchoreApiError,
    BadRequest,
    ConflictingRequest,
    HTTPNotImplementedError,
    ResourceNotFound,
)
from anchore_engine.clients.services.simplequeue import (
    LeaseAcquisitionFailedError,
    LeaseUnavailableError,
)
from anchore_engine.common.errors import AnchoreError
from anchore_engine.common.helpers import make_response_error
from anchore_engine.common.models.policy_engine import FeedGroupMetadata, FeedMetadata
from anchore_engine.db import FeedGroupMetadata as DbFeedGroupMetadata
from anchore_engine.db import FeedMetadata as DbFeedMetadata
from anchore_engine.services.policy_engine.engine.feeds import db, sync
from anchore_engine.services.policy_engine.engine.feeds.sync_utils import (
    GRYPE_DB_FEED_NAME,
)
from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask
from anchore_engine.services.policy_engine.engine.vulns.providers import (
    GrypeProvider,
    InvalidFeed,
    get_vulnerabilities_provider,
)
from anchore_engine.subsys import logger as log

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_feeds(refresh_counts=False):
    """
    GET /feeds

    :param refresh_counts: forcibly update the group counts (not normally necessary)
    :return:
    """

    provider = get_vulnerabilities_provider()

    if refresh_counts:
        provider.update_feed_group_counts()

    feeds = provider.get_feeds()
    for feed in feeds:
        feed.name = provider.display_mapper.get_display_name(internal_name=feed.name)

    return [feed.to_json() for feed in feeds]


def _marshall_feed_response(feed: DbFeedMetadata) -> FeedMetadata:
    """
    Old method for marshaling a feed. Currently being replaced by workflows driven by providers
    """
    if not feed:
        return ValueError(feed)

    feed_metadata = FeedMetadata()
    feed_metadata.name = feed.name
    feed_metadata.last_full_sync = feed.last_full_sync
    feed_metadata.created_at = feed.created_at
    feed_metadata.updated_at = feed.last_update
    feed_metadata.enabled = feed.enabled
    feed_metadata.groups = []

    for group in feed.groups:
        feed_metadata.groups.append(_marshall_group_response(group))

    return feed_metadata


def _marshall_group_response(group: DbFeedGroupMetadata) -> FeedGroupMetadata:
    """
    Old method for marshaling a feed's groups. Currently being replaced by workflows driven by providers
    """
    if not group:
        raise ValueError(group)

    feed_group_metadata = FeedGroupMetadata()
    feed_group_metadata.name = group.name
    feed_group_metadata.last_sync = group.last_sync
    feed_group_metadata.created_at = group.created_at
    feed_group_metadata.updated_at = group.last_update
    feed_group_metadata.enabled = group.enabled
    feed_group_metadata.record_count = group.count
    return feed_group_metadata


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
        except (LeaseAcquisitionFailedError, LeaseUnavailableError):
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
        except Exception as exc:
            log.exception("Error executing feed update task")
            return jsonify(make_response_error(exc, in_httpcode=500)), 500
        provider = get_vulnerabilities_provider()
        for feed_sync_result in result:
            feed_sync_result.feed = provider.display_mapper.get_display_name(
                internal_name=feed_sync_result.feed
            )

    return jsonify([asdict(sync_result) for sync_result in result]), 200


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def toggle_feed_enabled(feed, enabled):
    if type(enabled) != bool:
        raise BadRequest(message="state must be a boolean", detail={"value": enabled})

    provider = get_vulnerabilities_provider()
    internal_feed_name = provider.display_mapper.get_internal_name(feed)
    try:
        feed_metadata = provider.update_feed_enabled_status(internal_feed_name, enabled)

        if not feed_metadata:
            raise ResourceNotFound(feed, detail={})

        return feed_metadata.to_json(), 200

    except InvalidFeed:
        raise BadRequest(
            message="Feed not supported on configured vulnerability provider",
            detail={"feed": feed, "configured_provider": provider.get_config_name()},
        )
    except Exception as exc:
        log.error("Could not update feed enabled status")
        return jsonify(make_response_error(exc, in_httpcode=500)), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def toggle_group_enabled(feed, group, enabled):
    if type(enabled) != bool:
        raise BadRequest(message="state must be a boolean", detail={"value": enabled})
    provider = get_vulnerabilities_provider()
    internal_feed_name = provider.display_mapper.get_internal_name(feed)
    if isinstance(provider, GrypeProvider) and internal_feed_name == GRYPE_DB_FEED_NAME:
        raise HTTPNotImplementedError(
            message="Enabling and disabling groups for {} feed with the grype vulnerability provider enabled is not currently supported.".format(
                feed
            ),
            detail={},
        )
    session = db.get_session()
    try:
        feed_group_metadata = db.set_feed_group_enabled(
            session, internal_feed_name, group, enabled
        )
        if not feed_group_metadata:
            raise ResourceNotFound(group, detail={})

        session.flush()

        grp = _marshall_group_response(feed_group_metadata).to_json()
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
    provider = get_vulnerabilities_provider()
    internal_feed_name = provider.display_mapper.get_internal_name(feed)
    if isinstance(provider, GrypeProvider) and internal_feed_name == GRYPE_DB_FEED_NAME:
        raise HTTPNotImplementedError(
            message="Deleting the {} feed with the grype vulnerability provider enabled is not yet supported.".format(
                feed
            ),
            detail={},
        )
    session = db.get_session()
    try:
        feed_metadata = db.lookup_feed(db_session=session, feed_name=internal_feed_name)
        if not feed_metadata:
            raise ResourceNotFound(resource=feed, detail={})
        elif feed_metadata.enabled:
            raise ConflictingRequest(
                message="Cannot delete an enabled feed. Disable the feed first",
                detail={},
            )
    except AnchoreApiError:
        raise
    except Exception as exc:
        return jsonify(make_response_error(exc, in_httpcode=500)), 500
    finally:
        session.rollback()

    try:
        feed_metadata = sync.DataFeeds.delete_feed(internal_feed_name)
        if feed_metadata:
            return jsonify(_marshall_feed_response(feed_metadata).to_json()), 200
        else:
            raise ResourceNotFound(feed, detail={})
    except KeyError as exc:
        raise ResourceNotFound(resource=str(exc), detail={"feed": feed})
    except AnchoreApiError:
        raise
    except Exception as exc:
        return jsonify(make_response_error(exc, in_httpcode=500)), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_group(feed, group):
    provider = get_vulnerabilities_provider()
    internal_feed_name = provider.display_mapper.get_internal_name(feed)
    if isinstance(provider, GrypeProvider) and internal_feed_name == GRYPE_DB_FEED_NAME:
        raise HTTPNotImplementedError(
            message="Deleting individual groups for the {} feed with the grype vulnerability provider enabled is not yet supported.".format(
                feed
            ),
            detail={},
        )
    session = db.get_session()
    try:
        feed_group_metadata = db.lookup_feed_group(
            db_session=session, feed_name=internal_feed_name, group_name=group
        )
        if not feed_group_metadata:
            raise ResourceNotFound(group, detail={})
        elif feed_group_metadata.enabled:
            raise ConflictingRequest(
                message="Cannot delete an enabled feed group. Disable the feed group first",
                detail={},
            )
    except AnchoreApiError:
        raise
    except Exception as exc:
        return jsonify(make_response_error(exc, in_httpcode=500)), 500
    finally:
        session.rollback()

    try:
        feed_group_metadata = sync.DataFeeds.delete_feed_group(
            feed_name=internal_feed_name, group_name=group
        )
        log.info("Flushed group records {}".format(feed_group_metadata))
        if feed_group_metadata:
            return jsonify(_marshall_group_response(feed_group_metadata).to_json()), 200
        else:
            raise ResourceNotFound(group, detail={})
    except KeyError as exc:
        raise ResourceNotFound(resource=str(exc), detail={"feed": feed, "group": group})
    except AnchoreApiError:
        raise
    except Exception as exc:
        log.error("Could not flush feed group {}/{}".format(feed, group))
        return jsonify(make_response_error(exc, in_httpcode=500)), 500
