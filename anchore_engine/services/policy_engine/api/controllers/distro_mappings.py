"""
Controller for all synchronous web operations. These are handled by the main web service endpoint.

Async operations are handled by teh async_operations controller.

"""

import logging
import datetime

from flask import abort
from anchore_engine.db import get_thread_scoped_session as get_session, DistroMapping as DbDistroMapping
from anchore_engine.services.policy_engine.api.models import DistroMapping
from sqlalchemy.exc import IntegrityError
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED

log = logging.getLogger()
ANCHORE_PUBLIC_USER = '0'

authorizer = get_authorizer()

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_distro_mappings():
    """
    GET /distro_mappings

    :return: Array of DistroMapping objects
    """

    db = get_session()
    try:
        mappings = [DistroMapping(from_distro=x.from_distro, to_distro=x.to_distro, created_at=x.created_at, flavor=x.flavor).to_dict() for x in db.query(DbDistroMapping).all()]
        return mappings
    except Exception as e:
        log.exception('Error processing list_distro_mappings. Could not read db entities')
        abort(500)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def add_distro_mapping(distro_mapping):
    """
    POST /distro_mappings

    :param distro_mapping: a DistroMapping object from request body
    :return: listing of all distro mappings
    """
    dist_map = DistroMapping.from_dict(distro_mapping)
    db = get_session()
    try:
        new_mapping = DbDistroMapping()
        new_mapping.created_at = datetime.datetime.utcnow()
        new_mapping.from_distro = dist_map.from_distro
        new_mapping.to_distro = dist_map.to_distro
        new_mapping.flavor = dist_map.flavor
        db.add(new_mapping)
        db.commit()
    except IntegrityError as e:
        log.warn('Insertion of existing mapping name')
        db.rollback()
        abort(409)
    except Exception as e:
        log.exception('Error inserting new distro mapping')
        db.rollback()
        abort(500)

    return list_distro_mappings()

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_distro_mapping(from_distro):
    """
    DELETE /distro_mappings?from_distro=X

    :param distro_name:
    :return:
    """
    db = get_session()
    try:
        rec = db.query(DbDistroMapping).get(from_distro)
        if rec:
            db.delete(rec)
        else:
            pass
            # no-op
        db.commit()
    except Exception as e:
        log.exception('Error deleting distro mapping for: {}'.format(from_distro))
        db.rollback()
        abort(500)

    return list_distro_mappings()
