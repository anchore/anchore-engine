from anchore_engine.db import FeedMetadata, FeedGroupMetadata, get_session
from anchore_engine.subsys.caching import local_named_cache
from anchore_engine.subsys import logger

cache_name = "feed_group_metadata"


def lookup_feed(db_session, feed_name):
    if db_session is None or not db_session.is_active:
        raise ValueError("db_session must be an open, valid session")

    return db_session.query(FeedMetadata).filter_by(name=feed_name).one_or_none()


def lookup_feed_group(db_session, feed_name, group_name):
    if db_session is None or not db_session.is_active:
        raise ValueError("db_session must be an open, valid session")

    return (
        db_session.query(FeedGroupMetadata)
        .filter_by(name=group_name, feed_name=feed_name)
        .one_or_none()
    )


def set_feed_group_enabled(db_session, feed_name, group_name, is_enabled):
    """
    Update the group's enabled state

    :param db_session: active db session to use
    :param feed_name: string name of feed
    :param group_name: string group name
    :param is_enabled: boolean to set enabled flag
    :return:
    """
    if db_session is None or not db_session.is_active:
        raise ValueError("db_session must be an open, valid session")

    meta = (
        db_session.query(FeedGroupMetadata)
        .filter_by(name=group_name, feed_name=feed_name)
        .one_or_none()
    )
    if meta:
        meta.enabled = is_enabled

    return meta


def set_feed_enabled(db_session, feed_name, is_enabled):
    """
    Update the group's enabled state

    :param db_session: active db session to use
    :param feed_name: string name of feed
    :param is_enabled: boolean to set enabled flag
    :return:
    """
    if db_session is None or not db_session.is_active:
        raise ValueError("db_session must be an open, valid session")

    meta = db_session.query(FeedMetadata).filter_by(name=feed_name).one_or_none()
    if meta:
        meta.enabled = is_enabled

    return meta


def get_feed_json(db_session, feed_name):
    cache = local_named_cache(cache_name)
    cached = cache.lookup(feed_name)
    if cached:
        return cached

    meta_record = lookup_feed(db_session, feed_name)
    if meta_record:
        cache.cache_it(meta_record.name, meta_record.to_json())

    return cache.lookup(feed_name)


def get_feed_group_json(db_session, feed_name, group_name):
    found = None
    f = get_feed_json(db_session, feed_name)
    if f:
        found = [x for x in f.get("groups", []) if x.get("name") == group_name]
        if found:
            found = found[0]
    return found


def get_all_feeds_detached():
    """
    Returns a list of FeedMetadata objects populated with FeedGroupMetadata objects as returned by the db, but detached from the session.

    :return: list of FeedMetadata objects
    """
    db_session = get_session()
    try:
        feeds = get_all_feeds(db_session)
        response = []
        for f in feeds:
            t = f.to_detached()
            t.groups = [g.to_detached() for g in f.groups]
            response.append(t)

        return response
    except Exception as e:
        logger.exception("Could not get feed metadata")
        raise e
    finally:
        db_session.rollback()


def get_all_feed_groups_detached(feed_name):
    """
    Returns a list of FeedMetadata objects populated with FeedGroupMetadata objects as returned by the db, but detached from the session.

    :return: list of FeedMetadata objects
    """
    db_session = get_session()
    try:
        feeds = lookup_feed(db_session, feed_name)
        response = []
        for f in feeds:
            if f.groups:
                response.extend([g.to_detached() for g in f.groups])

        return response
    except Exception as e:
        logger.exception("Could not get feed metadata")
        raise e
    finally:
        db_session.rollback()


def get_feed_group_detached(feed_name, group_name):
    """
    Returns a list of FeedMetadata objects populated with FeedGroupMetadata objects as returned by the db, but detached from the session.

    :return: list of FeedMetadata objects
    """
    db_session = get_session()
    try:
        group = lookup_feed_group(db_session, feed_name, group_name)
        return group.to_detached() if group else None
    except Exception as e:
        logger.exception("Could not get feed metadata")
        raise e
    finally:
        db_session.rollback()


def get_all_feeds(db):
    return db.query(FeedMetadata).all()
