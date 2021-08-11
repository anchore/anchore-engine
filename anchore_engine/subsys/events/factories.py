from anchore_engine.subsys.events import UserAnalyzeImageCompleted


def fulltag_from_detail(image_detail: dict) -> str:
    """
    Return a fulltag string from the detail record

    :param image_detail:
    :return:
    """
    return (
        image_detail["registry"]
        + "/"
        + image_detail["repo"]
        + ":"
        + image_detail["tag"]
    )


def analysis_complete_notification_factory(
    account,
    image_digest: str,
    last_analysis_status: str,
    analysis_status: str,
    image_detail: dict,
    annotations: dict,
) -> UserAnalyzeImageCompleted:
    """
    Return a constructed UserAnalysImageCompleted event from the input data

    :param account:
    :param image_digest:
    :param last_analysis_status:
    :param analysis_status:
    :param image_detail:
    :param annotations:
    :return:
    """

    payload = {
        "last_eval": {
            "imageDigest": image_digest,
            "analysis_status": last_analysis_status,
            "annotations": annotations,
        },
        "curr_eval": {
            "imageDigest": image_digest,
            "analysis_status": analysis_status,
            "annotations": annotations,
        },
        "subscription_type": "analysis_update",
        "annotations": annotations or {},
    }

    fulltag = fulltag_from_detail(image_detail)

    return UserAnalyzeImageCompleted(user_id=account, full_tag=fulltag, data=payload)
