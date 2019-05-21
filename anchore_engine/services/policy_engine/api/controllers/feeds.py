from flask import jsonify

from anchore_engine.common.errors import AnchoreError
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED
from anchore_engine.clients.services.simplequeue import LeaseAcquisitionFailedError, LeaseUnavailableError
from anchore_engine.common.helpers import make_response_error
from anchore_engine.services.policy_engine.api.models import FeedMetadata, FeedGroupMetadata
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds
from anchore_engine.services.policy_engine.engine.tasks import FeedsUpdateTask
from anchore_engine.subsys import logger as log

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_feeds(include_counts=False):
    """
    GET /feeds
    :return:
    """

    f = DataFeeds.instance()
    meta = f.list_metadata()

    response = []

    for feed in meta:
        i = FeedMetadata()
        i.name = feed.name
        i.last_full_sync = feed.last_full_sync.isoformat() if feed.last_full_sync else None
        i.created_at = feed.created_at.isoformat() if feed.created_at else None
        i.updated_at = feed.last_update.isoformat() if feed.last_update else None
        i.groups = []

        for group in feed.groups:
            g = FeedGroupMetadata()
            g.name = group.name
            g.last_sync = group.last_sync.isoformat() if group.last_sync else None
            g.created_at = group.created_at.isoformat() if group.created_at else None

            if include_counts:
                # Compute count (this is slow)
                g.record_count = f.records_for(i.name, g.name)
            else:
                g.record_count = None

            i.groups.append(g.to_dict())

        response.append(i.to_dict())

    return jsonify(response)


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
            log.exception('Could not acquire lock on feed sync, likely another sync already in progress')
            return make_response_error('Feed sync lock already held', in_httpcode=409,
                                       details={'error_codes': [AnchoreError.FEED_SYNC_ALREADY_IN_PROGRESS.name], 'message': AnchoreError.FEED_SYNC_ALREADY_IN_PROGRESS.value}), 409
        except Exception as e:
            log.exception('Error executing feed update task')
            return jsonify(make_response_error(e, in_httpcode=500)), 500

    return jsonify(result), 200
