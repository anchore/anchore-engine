import datetime

import sqlalchemy
from dateutil import parser as dateparser
from sqlalchemy import func

from anchore_engine import db
from anchore_engine.db import Event


def get_byfilter(
    userId,
    session=None,
    event_type=None,
    since=None,
    before=None,
    page=1,
    limit=100,
    **dbfilter
):
    if not session:
        session = db.Session

    ret = {"results": [], "next_page": False, "item_count": 0, "page": page}

    if page > 1:
        # inner query: execute row_number() on the timestamp column over the results of query
        resq = session.query(
            Event,
            func.row_number().over(order_by=Event.timestamp.desc()).label("rownum"),
        ).filter(Event.resource_user_id == userId)

        if dbfilter:
            resq = resq.filter_by(**dbfilter)
        if before:
            resq = resq.filter(Event.timestamp < before)
        if since:
            resq = resq.filter(Event.timestamp > since)

        if event_type:
            event_type_like = event_type.replace("*", "%")
            if event_type == event_type_like:
                resq = resq.filter(Event.type == event_type)
            else:
                resq = resq.filter(Event.type.like(event_type_like))

        start = (page - 1) * limit
        end = (
            start + limit + 1
        )  # get one more result than requested, required to indicate next token

        # outer query: filter range of results that match the attached row numbers from the inner query
        resq = resq.from_self(Event)
        resq = resq.filter(
            sqlalchemy.text("rownum > {} and rownum <= {}".format(start, end))
        ).order_by(sqlalchemy.text("rownum"))

    else:
        # Query the first limit+1 results and call it a day
        resq = session.query(Event).filter(Event.resource_user_id == userId)

        if dbfilter:
            resq = resq.filter_by(**dbfilter)
        if before:
            resq = resq.filter(Event.timestamp < before)
        if since:
            resq = resq.filter(Event.timestamp > since)

        if event_type:
            event_type_like = event_type.replace("*", "%")
            if event_type == event_type_like:
                resq = resq.filter(Event.type == event_type)
            else:
                resq = resq.filter(Event.type.like(event_type_like))

        # sqlalchemy does not like it if limit is applied before filter
        resq = resq.order_by(Event.timestamp.desc()).limit(limit + 1)

    # # Query for counting total number of results matching the filters
    # countq = session.query(func.count(Event.generated_uuid)).filter(Event.resource_user_id == userId).order_by(None)
    # if dbfilter:
    #     countq = resq.filter_by(**dbfilter)
    # if before:
    #     countq = resq.filter(Event.timestamp < before)
    # if since:
    #     countq = resq.filter(Event.timestamp > since)
    #
    # # Execute count query
    # ret['total_count'] = countq.scalar()

    # Execute limit bound query
    for db_event in resq.all():
        if len(ret["results"]) < limit:
            ret["results"].append(_db_to_dict(db_event))
        else:
            ret["next_page"] = True
            break

    ret["item_count"] = len(ret["results"])

    return ret


def get_byevent_id(userId, eventId, session=None):
    if not session:
        session = db.Session

    db_event = (
        session.query(Event)
        .filter(Event.resource_user_id == userId, Event.generated_uuid == eventId)
        .one_or_none()
    )

    return _db_to_dict(db_event) if db_event else None


def add(msg, session=None):
    if not session:
        session = db.Session

    db_event = _dict_to_db(msg)

    session.add(db_event)
    session.flush()
    res = db_event.to_detached()

    return _db_to_dict(res)


def delete_byfilter(userId, session=None, since=None, before=None, **dbfilter):
    if not session:
        session = db.Session

    ret = []

    query = session.query(Event).filter(Event.resource_user_id == userId)

    if before:
        query = query.filter(Event.timestamp < before)

    if since:
        query = query.filter(Event.timestamp > since)

    if dbfilter:
        query = query.filter_by(**dbfilter)

    for db_event in query:
        ret.append(db_event.generated_uuid)
        session.delete(db_event)

    return ret


def delete_byevent_id(userId, eventId, session=None):
    if not session:
        session = db.Session

    ret = False

    db_event = (
        session.query(Event)
        .filter(Event.resource_user_id == userId, Event.generated_uuid == eventId)
        .one_or_none()
    )
    if db_event:
        ret = True
        session.delete(db_event)

    return ret


def _db_to_dict(db_event):
    msg = {"event": {}, "generated_uuid": None, "created_at": None}

    for key, value in vars(db_event).items():
        if key.startswith("_"):
            continue

        if key in ["generated_uuid", "created_at"]:
            msg[key] = (
                value if type(value) != datetime.datetime else _format_timestamp(value)
            )
        else:
            if key.startswith("resource") or key.startswith("source"):
                key1, key2 = key.split("_", 1)
                if key1 not in msg["event"]:
                    msg["event"][key1] = {}
                msg["event"][key1][key2] = (
                    value
                    if type(value) != datetime.datetime
                    else _format_timestamp(value)
                )
            else:
                msg["event"][key] = (
                    value
                    if type(value) != datetime.datetime
                    else _format_timestamp(value)
                )

    return msg


def _dict_to_db(msg):
    db_event = Event()

    event_msg = {}
    event_msg.update(msg)

    if event_msg.get("source", None):
        db_event.source_servicename = event_msg["source"].get("servicename", None)
        db_event.source_hostid = event_msg["source"].get("hostid", None)
        db_event.source_base_url = event_msg["source"].get("base_url", None)
        db_event.source_request_id = event_msg["source"].get("request_id", None)

    if event_msg.get("resource", None):
        db_event.resource_user_id = event_msg["resource"].get("user_id", None)
        db_event.resource_id = event_msg["resource"].get("id", None)
        db_event.resource_type = event_msg["resource"].get("type", None)

    db_event.type = event_msg["type"]
    db_event.level = event_msg["level"]
    db_event.message = event_msg["message"]
    db_event.details = event_msg.get("details", {})
    db_event.timestamp = dateparser.parse(event_msg["timestamp"])

    return db_event


def _format_timestamp(ts):
    return ts.isoformat() + "Z"
