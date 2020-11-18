import hashlib
import time

from anchore_engine import db
from anchore_engine.db import Subscription


def _compute_subscription_id(userId, subscription_key, subscription_type):
    return hashlib.md5(
        "+".join([userId, subscription_key, subscription_type]).encode("utf-8")
    ).hexdigest()


def _prep_payload(subscription_id, inobj):
    # prep the input object
    if not inobj:
        inobj = {}

    inobj["subscription_id"] = subscription_id

    inobj.pop("userId", None)
    inobj.pop("last_updated", None)
    inobj.pop("created_at", None)

    return inobj


def _new_subscription_record(
    userId, subscription_id, subscription_key, subscription_type, inobj
):
    our_result = Subscription(
        subscription_id=subscription_id,
        userId=userId,
        subscription_key=subscription_key,
        subscription_type=subscription_type,
    )
    our_result.update(inobj)

    return our_result


def create_without_saving(userId, subscription_key, subscription_type, inobj):
    subscription_id = _compute_subscription_id(
        userId, subscription_key, subscription_type
    )
    inobj = _prep_payload(subscription_id, inobj)
    our_result = _new_subscription_record(
        userId, subscription_id, subscription_key, subscription_type, inobj
    )

    return our_result.to_dict()


def add(userId, subscription_key, subscription_type, inobj, session=None):
    if not session:
        session = db.Session

    subscription_id = _compute_subscription_id(
        userId, subscription_key, subscription_type
    )
    inobj = _prep_payload(subscription_id, inobj)

    our_result = (
        session.query(Subscription)
        .filter_by(
            subscription_id=subscription_id,
            userId=userId,
            subscription_key=subscription_key,
            subscription_type=subscription_type,
        )
        .first()
    )
    if not our_result:
        our_result = _new_subscription_record(
            userId, subscription_id, subscription_key, subscription_type, inobj
        )
        session.add(our_result)
    else:
        our_result.update(inobj)

    return True


def get_all_byuserId(userId, limit=None, session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Subscription).filter_by(userId=userId)
    if limit:
        our_results = our_results.limit(int(limit))

    for result in our_results:
        ret.append(result.to_dict())

    return ret


def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    our_results = session.query(Subscription)
    for result in our_results:
        ret.append(result.to_dict())

    return ret


def get(userId, subscription_id, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = (
        session.query(Subscription)
        .filter_by(userId=userId, subscription_id=subscription_id)
        .first()
    )

    if result:
        ret = result.to_dict()

    return ret


def is_active(account, subscription_id, session=None):
    """
    Returns the subscription id of the record if one exists for the account and subscription id
    """

    if not session:
        session = db.Session

    result = (
        session.query(Subscription.subscription_id)
        .filter_by(userId=account, subscription_id=subscription_id, active=True)
        .scalar()
    )

    return result


def get_byfilter(userId, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    dbfilter["userId"] = userId

    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            ret.append(result.to_dict())

    return ret


def get_bysubscription_key(userId, subscription_key, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(Subscription).filter_by(
        userId=userId, subscription_key=subscription_key
    )

    if results:
        for result in results:
            obj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )
            ret.append(obj)

    return ret


def upsert(userId, subscription_key, subscription_type, inobj, session=None):
    return add(userId, subscription_key, subscription_type, inobj, session=session)


def update_subscription_value(
    account, subscription_id, subscription_value, session=None
):
    """
    Lookup the record and update subscription value only for an existing record
    """
    if not session:
        session = db.Session

    result = (
        session.query(Subscription)
        .filter_by(subscription_id=subscription_id, userId=account)
        .one_or_none()
    )
    if result:
        result.subscription_value = subscription_value

    return result


def delete(userId, subscriptionId, remove=False, session=None):
    if not session:
        session = db.Session

    ret = False

    dbfilter = {"userId": userId, "subscription_id": subscriptionId}
    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update(
                    {
                        "record_state_key": "to_delete",
                        "record_state_val": str(time.time()),
                    }
                )

            ret = True

    return ret


def delete_bysubscription_key(userId, subscription_key, remove=False, session=None):
    if not session:
        session = db.Session

    ret = False

    results = session.query(Subscription).filter_by(
        userId=userId, subscription_key=subscription_key
    )
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update(
                    {
                        "record_state_key": "to_delete",
                        "record_state_val": str(time.time()),
                    }
                )

            ret = True

    return ret


def delete_byfilter(userId, remove=False, session=None, **dbfilter):
    if not session:
        session = db.Session

    ret = False

    dbfilter["userId"] = userId

    results = session.query(Subscription).filter_by(**dbfilter)
    if results:
        for result in results:
            if remove:
                session.delete(result)
            else:
                result.update(
                    {
                        "record_state_key": "to_delete",
                        "record_state_val": str(time.time()),
                    }
                )
            ret = True

    return ret
