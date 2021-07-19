from sqlalchemy import and_, desc, or_

from anchore_engine import db
from anchore_engine.db import CatalogImage, CatalogImageDocker
from anchore_engine.subsys import logger


def add_record(input_image_record, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    # image_record.pop('created_at', None)
    image_record.pop("last_updated", None)

    our_result = (
        session.query(CatalogImage)
        .filter_by(
            imageDigest=image_record["imageDigest"],
            userId=image_record["userId"],
            image_type=image_record["image_type"],
        )
        .first()
    )
    if not our_result:
        # add the image detail
        image_detail = image_record.pop("image_detail")
        if image_record["image_type"] == "docker":
            # add the detail records
            for tag_record in image_detail:
                if image_record["created_at"]:
                    tag_record["created_at"] = image_record["created_at"]
                rc = db.db_catalog_image_docker.add_record(tag_record, session=session)

        our_result = CatalogImage(**image_record)
        session.add(our_result)

    return True


def update_record(input_image_record, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    image_record.pop("created_at", None)
    image_record.pop("last_updated", None)

    our_result = (
        session.query(CatalogImage)
        .filter_by(
            imageDigest=image_record["imageDigest"],
            userId=image_record["userId"],
            image_type=image_record["image_type"],
        )
        .first()
    )
    if our_result:
        image_detail = image_record.pop("image_detail")
        if image_record["image_type"] == "docker":

            # add the detail records
            imageId = None
            for tag_record in image_detail:
                rc = db.db_catalog_image_docker.add_record(tag_record, session=session)
                rc = db.db_catalog_image_docker.update_record(
                    tag_record, session=session
                )
                if "imageId" in tag_record and tag_record["imageId"]:
                    imageId = tag_record["imageId"]

            # handle case where there may have been new image_detail records added before imageId element was ready, sync all image_details with latest imageId
            try:
                if imageId:
                    all_tag_records = db.db_catalog_image_docker.get_alltags(
                        image_record["imageDigest"],
                        image_record["userId"],
                        session=session,
                    )
                    for tag_record in all_tag_records:
                        if "imageId" not in tag_record or (
                            "imageId" in tag_record and not tag_record["imageId"]
                        ):
                            tag_record["imageId"] = imageId
                            rc = db.db_catalog_image_docker.update_record(
                                tag_record, session=session
                            )
            except Exception as err:
                logger.warn(
                    "unable to update all image_details with found imageId: " + str(err)
                )

        our_result.update(image_record)

    return True


def update_record_image_detail(input_image_record, updated_image_detail, session=None):
    if not session:
        session = db.Session

    image_record = {}
    image_record.update(input_image_record)

    image_record.pop("created_at", None)
    image_record.pop("last_updated", None)

    if image_record["image_type"] == "docker":
        for tag_record in updated_image_detail:
            if tag_record not in image_record["image_detail"]:
                image_record["image_detail"].append(tag_record)
                return update_record(image_record, session=session)

    return image_record


def _lookup_image(account_id, image_digest, session):
    return (
        session.query(CatalogImage)
        .filter(
            or_(
                CatalogImage.imageDigest == image_digest,
                CatalogImage.parentDigest == image_digest,
            ),
            CatalogImage.userId == account_id,
        )
        .order_by(desc(CatalogImage.created_at))
        .first()
    )


def get(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    ret = {}

    result = _lookup_image(userId, imageDigest, session)
    if result:
        dbobj = dict(
            (key, value)
            for key, value in vars(result).items()
            if not key.startswith("_")
        )
        ret = dbobj
        imageDigest = dbobj["imageDigest"]
        if dbobj["image_type"] == "docker":
            imgobj = db.db_catalog_image_docker.get_alltags(
                imageDigest, userId, session=session
            )
            ret["image_detail"] = imgobj

    return ret


def get_image_status(account_id, image_digest, session=None):
    if not session:
        session = db.Session

    result = _lookup_image(account_id, image_digest, session)

    if result:
        return result.image_status
    else:
        raise Exception("No image found with digest %s" % image_digest)


def update_image_status(account_id, image_digest, new_status, session=None):
    if not session:
        session = db.Session

    result = _lookup_image(account_id, image_digest, session)

    if result and result.image_status != new_status:
        result.image_status = new_status
    else:
        raise Exception("No image found with digest %s" % image_digest)

    return result


def get_docker_created_at(record):
    latest_ts = 0

    try:
        for image_detail in record["image_detail"]:
            try:
                if image_detail["created_at"] > latest_ts:
                    latest_ts = image_detail["created_at"]
            except:
                pass
    except:
        pass
    return latest_ts


def get_created_at(record):
    if "created_at" in record and record["created_at"]:
        return record["created_at"]
    return 0


def get_byimagefilter(
    userId,
    image_type,
    dbfilter={},
    onlylatest=False,
    image_status="active",
    analysis_status=None,
    session=None,
):
    if not session:
        session = db.Session

    ret = []

    ret_results = []
    if image_type == "docker":
        results = db.db_catalog_image_docker.get_byfilter(
            userId, session=session, **dbfilter
        )
        latest = None
        for result in results:
            imageDigest = result["imageDigest"]
            dbobj = get(imageDigest, userId, session=session)

            if (image_status is None or dbobj["image_status"] == image_status) and (
                analysis_status is None or dbobj["analysis_status"] == analysis_status
            ):
                if not latest:
                    latest = dbobj

                ret_results.append(dbobj)

    ret = []
    if not onlylatest:
        ret = ret_results
    else:
        if latest:
            ret = [latest]

    return ret


def get_all_tagsummary(userId, session=None, image_status=None):
    query = session.query(
        CatalogImage.imageDigest,
        CatalogImage.parentDigest,
        CatalogImageDocker.registry,
        CatalogImageDocker.repo,
        CatalogImageDocker.tag,
        CatalogImage.analysis_status,
        CatalogImageDocker.created_at,
        CatalogImageDocker.imageId,
        CatalogImage.analyzed_at,
        CatalogImageDocker.tag_detected_at,
        CatalogImage.image_status,
    ).filter(
        and_(
            CatalogImage.userId == userId,
            CatalogImage.imageDigest == CatalogImageDocker.imageDigest,
            CatalogImageDocker.userId == userId,
        )
    )

    if (
        image_status and isinstance(image_status, list) and "all" not in image_status
    ):  # filter only if specific states are input and != all
        query = query.filter(CatalogImage.image_status.in_(image_status))

    ret = []
    for idig, pdig, reg, repo, tag, astat, cat, iid, anat, dat, istat in query:
        ret.append(
            {
                "imageDigest": idig,
                "parentDigest": pdig,
                "fulltag": reg + "/" + repo + ":" + tag,
                "analysis_status": astat,
                "created_at": cat,
                "imageId": iid,
                "analyzed_at": anat,
                "tag_detected_at": dat,
                "image_status": istat,
            }
        )

    return ret


def get_all_byuserId(
    userId,
    limit=None,
    session=None,
    image_status_filter="active",
    analysis_status_filter=None,
):
    if not session:
        session = db.Session

    ret = []

    results = (
        session.query(CatalogImage)
        .filter_by(userId=userId)
        .order_by(desc(CatalogImage.created_at))
    )

    # Treat 'all' as no filter
    if image_status_filter and image_status_filter != "all":
        results = results.filter(CatalogImage.image_status == image_status_filter)

    if analysis_status_filter:
        results = results.filter(CatalogImage.analysis_status == analysis_status_filter)

    if limit:
        results = results.limit(int(limit))

    if results:
        # get all the tags in single DB query, hash by imageDigest
        alltags = db.db_catalog_image_docker.get_all(userId, session=session)
        tagdata = {}
        for tag in alltags:
            if tag["imageDigest"] not in tagdata:
                tagdata[tag["imageDigest"]] = []
            tagdata[tag["imageDigest"]].append(tag)

        for result in results:
            dbobj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )

            imageDigest = dbobj["imageDigest"]
            if dbobj["image_type"] == "docker":
                if imageDigest in tagdata:
                    dbobj["image_detail"] = tagdata[imageDigest]
                else:
                    dbobj["image_detail"] = []

            ret.append(dbobj)
    return ret


def get_all_iter(session=None):
    if not session:
        session = db.Session

    for top_result in session.query(
        CatalogImage.imageDigest, CatalogImage.userId
    ).order_by(desc(CatalogImage.created_at)):
        result = (
            session.query(CatalogImage)
            .filter_by(imageDigest=top_result.imageDigest, userId=top_result.userId)
            .first()
        )
        dbobj = dict(
            (key, value)
            for key, value in vars(result).items()
            if not key.startswith("_")
        )
        imageDigest = dbobj["imageDigest"]
        userId = dbobj["userId"]
        if dbobj["image_type"] == "docker":
            imgobj = db.db_catalog_image_docker.get_alltags(
                imageDigest, userId, session=session
            )
            dbobj["image_detail"] = imgobj
        yield dbobj


def get_all(session=None):
    if not session:
        session = db.Session

    ret = []

    results = session.query(CatalogImage).order_by(desc(CatalogImage.created_at))
    if results:
        for result in results:
            dbobj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )
            imageDigest = dbobj["imageDigest"]
            userId = dbobj["userId"]
            if dbobj["image_type"] == "docker":
                imgobj = db.db_catalog_image_docker.get_alltags(
                    imageDigest, userId, session=session
                )
                dbobj["image_detail"] = imgobj
            ret.append(dbobj)

    return ret


def get_byfilter(userId, session=None, **kwargs):
    if not session:
        session = db.Session

    ret = []

    kwargs["userId"] = userId

    results = (
        session.query(CatalogImage)
        .filter_by(**kwargs)
        .order_by(desc(CatalogImage.created_at))
    )
    if results:
        for result in results:
            dbobj = dict(
                (key, value)
                for key, value in vars(result).items()
                if not key.startswith("_")
            )
            imageDigest = dbobj["imageDigest"]
            userId = dbobj["userId"]
            if dbobj["image_type"] == "docker":
                imgobj = db.db_catalog_image_docker.get_alltags(
                    imageDigest, userId, session=session
                )
                dbobj["image_detail"] = imgobj
            ret.append(dbobj)

    return ret


def get_all_by_filter(session=None, **kwargs):
    if not session:
        session = db.Session

    ret = []

    query = (
        session.query(CatalogImage)
        .filter_by(**kwargs)
        .order_by(desc(CatalogImage.created_at))
    )
    for result in query:
        dbobj = dict(
            (key, value)
            for key, value in vars(result).items()
            if not key.startswith("_")
        )
        imageDigest = dbobj["imageDigest"]
        userId = dbobj["userId"]
        if dbobj["image_type"] == "docker":
            imgobj = db.db_catalog_image_docker.get_alltags(
                imageDigest, userId, session=session
            )
            dbobj["image_detail"] = imgobj
        ret.append(dbobj)

    return ret


def delete(imageDigest, userId, session=None):
    if not session:
        session = db.Session

    our_results = session.query(CatalogImage).filter(
        or_(
            CatalogImage.imageDigest == imageDigest,
            CatalogImage.parentDigest == imageDigest,
        ),
        CatalogImage.userId == userId,
    )

    for result in our_results:
        imageDigest = result.imageDigest
        session.delete(result)

    our_results = session.query(CatalogImageDocker).filter_by(
        imageDigest=imageDigest, userId=userId
    )
    for result in our_results:
        session.delete(result)

    return True


def get_oldest_images_with_limit(session, account, max_images):
    """
    This method will return the oldest images which exceed the max_images limit

    Ex. max_images = 1000
        images_in_anchore = 1100

    This method will return the image digests of the oldest 100 images (regardless of account)

    :param session: DB Session
    :param account: The account name (maps to userId in catalog_images)
    :param max_images: This is the maximum image count for the Anchore Deployment. Must be a positive integer.
                       Based on the number of images in Anchore, this will determine the number returned images
    """
    if max_images < 0:
        logger.warn(
            "Max images is negative, cannot transition images according to max_images_per_account setting"
        )
        return

    image_count = (
        session.query(CatalogImage)
        .filter(
            CatalogImage.analysis_status == "analyzed", CatalogImage.userId == account
        )
        .count()
    )
    limit = image_count - max_images

    if limit <= 0:
        logger.debug(
            "Limit is negative, no images to transition according to max_images_per_account setting: image_count={}, max_images={}".format(
                image_count, max_images
            )
        )
        return

    select_fields = [CatalogImageDocker, CatalogImage]

    qry = (
        session.query(*select_fields)
        .join(
            CatalogImage,
            and_(
                CatalogImageDocker.userId == CatalogImage.userId,
                CatalogImageDocker.imageDigest == CatalogImage.imageDigest,
            ),
        )
        .filter(
            CatalogImage.analysis_status == "analyzed",
            CatalogImage.userId == account,
        )
        .order_by(CatalogImage.analyzed_at.asc())
        .limit(limit)
    )

    return qry
