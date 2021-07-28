from sqlalchemy import and_, or_, desc

from anchore_engine import db
from anchore_engine.db import CatalogImageDocker, CatalogImage
from anchore_engine.subsys import logger


def update_record(record, session=None):
    if not session:
        session = db.Session

    our_result = (
        session.query(CatalogImageDocker)
        .filter_by(
            imageDigest=record["imageDigest"],
            userId=record["userId"],
            tag=record["tag"],
            repo=record["repo"],
            registry=record["registry"],
        )
        .first()
    )
    if our_result:
        our_result.update(record)

    return True


def add_record(record, session=None):
    if not session:
        session = db.Session

    our_result = (
        session.query(CatalogImageDocker)
        .filter_by(
            imageDigest=record["imageDigest"],
            userId=record["userId"],
            tag=record["tag"],
            repo=record["repo"],
            registry=record["registry"],
        )
        .first()
    )
    if not our_result:
        our_result = CatalogImageDocker(**record)
        session.add(our_result)

    return True


def add(
    imageDigest,
    userId,
    tag,
    registry=None,
    user=None,
    repo=None,
    digest=None,
    imageId=None,
    dockerfile=None,
    tag_detected_at=None,
    session=None,
):
    if not session:
        session = db.Session

    dbobj = {
        "registry": registry,
        "user": user,
        "repo": repo,
        "digest": digest,
        "imageId": imageId,
        "dockerfile": dockerfile,
    }
    if tag_detected_at:
        dbobj["tag_detected_at"] = tag_detected_at

    our_result = (
        session.query(CatalogImageDocker)
        .filter_by(imageDigest=imageDigest, userId=userId, tag=tag)
        .first()
    )
    if not our_result:
        our_result = CatalogImageDocker(imageDigest=imageDigest, userId=userId, tag=tag)
        our_result.update(dbobj)
        session.add(our_result)
    else:
        our_result.update(dbobj)

    return True


def update(
    imageDigest,
    userId,
    tag,
    registry=None,
    user=None,
    repo=None,
    digest=None,
    imageId=None,
    dockerfile=None,
    tag_detected_at=None,
    session=None,
):
    return add(
        imageDigest,
        userId,
        tag,
        registry=registry,
        user=user,
        repo=repo,
        digest=digest,
        imageId=imageId,
        dockerfile=dockerfile,
        session=session,
    )


def get_byfilter(userId, session=None, **kwargs):
    if not session:
        session = db.Session

    ret = []

    kwargs["userId"] = userId

    results = (
        session.query(CatalogImageDocker)
        .filter_by(**kwargs)
        .order_by(desc(CatalogImageDocker.created_at))
    )
    for result in results:
        dbobj = dict(
            (key, value)
            for key, value in vars(result).items()
            if not key.startswith("_")
        )
        ret.append(dbobj)

    return ret


def get_alltags(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImageDocker).filter_by(
        imageDigest=imageDigest, userId=userId
    )
    if results:
        for result in results:
            dbobj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )
            # dbobj = result.__dict__
            # dbobj.pop('_sa_instance_state', None)
            ret.append(dbobj)

    return ret


def get(imageDigest, userId, tag, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = (
        session.query(CatalogImageDocker)
        .filter_by(imageDigest=imageDigest, userId=userId, tag=tag)
        .first()
    )
    if result:
        dbobj = dict(
            (key, value)
            for key, value in vars(result).items()
            if not key.startswith("_")
        )
        ret = dbobj

    return ret


def get_all(userId, session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImageDocker).filter_by(userId=userId)
    if results:
        for result in results:
            dbobj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )
            ret.append(dbobj)

    return ret


def delete(imageDigest, userId, tag, session=None):
    if not session:
        session = db.Session

    return True


def get_tag_histories(session, userId, registries=None, repositories=None, tags=None):
    """
    registries, repositories, and tags are lists of filter strings (wildcard '*' allowed)

    Returns a query to iterate over matches in tag sorted ascending, and tag date descending order
    :param session:
    :param userId:
    :param registries:
    :param repositories:
    :param tags:
    :return: constructed query to execute/iterate over that returns tuples of (CatalogImageDocker, CatalogImage) that match userId/account and digest
    """
    select_fields = [CatalogImageDocker, CatalogImage]

    order_by_fields = [
        CatalogImageDocker.registry.asc(),
        CatalogImageDocker.repo.asc(),
        CatalogImageDocker.tag.asc(),
        CatalogImageDocker.tag_detected_at.desc(),
    ]

    qry = (
        session.query(*select_fields)
        .join(
            CatalogImage,
            and_(
                CatalogImageDocker.userId == CatalogImage.userId,
                CatalogImageDocker.imageDigest == CatalogImage.imageDigest,
            ),
        )
        .filter(CatalogImage.userId == userId)
        .order_by(*order_by_fields)
    )

    query_tuples = [
        (CatalogImageDocker.registry, registries),
        (CatalogImageDocker.repo, repositories),
        (CatalogImageDocker.tag, tags),
    ]
    for field, filters in query_tuples:
        if not filters:
            continue

        wildcarded = []
        exact = []
        for r in filters:
            if r.strip() == "*":
                continue

            if "*" in r:
                wildcarded.append(r)
            else:
                exact.append(r)

        conditions = []
        if wildcarded:
            for w in wildcarded:
                conditions.append(field.like(w.replace("*", "%")))

        if exact:
            conditions.append(field.in_(exact))

        if conditions:
            qry = qry.filter(or_(*conditions))

    logger.debug("Constructed tag history query: {}".format(qry))
    return qry
