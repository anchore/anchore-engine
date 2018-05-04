import connexion
import time

from anchore_engine import db
from anchore_engine.db import db_policyeval
#import catalog_impl
from anchore_engine.services.catalog import catalog_impl
from anchore_engine.api_utils import pass_user_context
import anchore_engine.services.common
from anchore_engine.subsys import logger
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus

from anchore_engine.subsys.metrics import flask_metrics, flask_metric_name, enabled as flask_metrics_enabled

def get_evals(policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False):
    """
    GET /evals

    :param bodycontent:
    :return:
    """
    httpcode = 500

    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            if newest_only:
                evals = list_evals_impl(session, userId=user_id, policyId=policyId, imageDigest=imageDigest, tag=tag,
                                        evalId=evalId)
            else:
                evals = list_evals_impl(session, userId=user_id, policyId=policyId, imageDigest=imageDigest, tag=tag, evalId=evalId)

            if not evals:
                httpcode = 404
                raise Exception("eval not found in DB")

        return evals, 200

    except Exception as err:
        return str(anchore_engine.services.common.make_response_error(err, in_httpcode=httpcode)), 500

    # return (return_object, httpcode)
    #     httpcode = 500
    #     return_object = str(err)


def add_eval(bodycontent):
    """
    POST /evals
    :param bodycontent:
    :return:
    """

    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            return_object, httpcode = upsert_eval(session, userId=user_id, record=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def update_eval(bodycontent):
    """
    PUT /evals

    :param bodycontent:
    :return:
    """
    try:
        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            return_object, httpcode = upsert_eval(session, userId=user_id, record=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def delete_eval(bodycontent):
    """
    DELETE /evals
    :param bodycontent:
    :return:
    """
    httpcode = 500
    try:

        request_inputs = anchore_engine.services.common.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']
        policyId = imageDigest = tag = evalId = None

        if bodycontent:
            policyId = bodycontent.get('policyId')
            imageDigest = bodycontent.get('imageDigest')
            tag = bodycontent.get('tag')
            evalId = bodycontent.get('evalId')

        with db.session_scope() as session:
            if delete_evals_impl(session, userId=user_id, policyId=policyId, imageDigest=imageDigest, tag=tag, evalId=evalId):
                httpcode = 200
            else:
                httpcode = 500
                raise Exception('Error processing policy evaluation deletion with content: {}'.format(bodycontent))

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


def list_evals_impl(dbsession, userId, policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False):
    logger.debug("looking up eval record: " + userId)


    # set up the filter based on input
    dbfilter = {}

    if policyId is not None:
        dbfilter['policyId'] = policyId

    if imageDigest is not None:
        dbfilter['imageDigest'] = imageDigest

    if tag is not None:
        dbfilter['tag'] = tag

    if evalId is not None:
        dbfilter['evalId'] = evalId


    # perform an interactive eval to get/install the latest
    try:
        logger.debug("performing eval refresh: " + str(dbfilter))
        imageDigest = dbfilter['imageDigest']
        if 'tag' in dbfilter:
            evaltag = dbfilter['tag']
        else:
            evaltag = None

        if 'policyId' in dbfilter:
            policyId = dbfilter['policyId']
        else:
            policyId = None

        rc = catalog_impl.perform_policy_evaluation(userId, imageDigest, dbsession, evaltag=evaltag, policyId=policyId)

    except Exception as err:
        logger.error(
            "interactive eval failed, will return any in place evaluation records - exception: " + str(err))

    records = db_policyeval.tsget_byfilter(userId, session=dbsession, **dbfilter)
    # Return None instead?
    #if not records:
    #    raise Exception("eval not found in DB")

    return records


def delete_evals_impl(dbsession, userId, policyId=None, imageDigest=None, tag=None, evalId=None):
    # set up the filter based on input
    dbfilter = {}

    if policyId is not None:
        dbfilter['policyId'] = policyId

    if imageDigest is not None:
        dbfilter['imageDigest'] = imageDigest

    if tag is not None:
        dbfilter['tag'] = tag

    if evalId is not None:
        dbfilter['evalId'] = evalId

    logger.debug("looking up eval record: " + userId)

    if not dbfilter:
        raise Exception("not enough detail in body to find records to delete")

    rc = db_policyeval.delete_byfilter(userId, session=dbsession, **dbfilter)
    if not rc:
        raise Exception("DB delete failed")
    else:
        return True


def upsert_eval(dbsession, userId, record):
    rc = db_policyeval.tsadd(record['policyId'], userId, record['imageDigest'], record['tag'],
                             record['final_action'],
                             {'policyeval': record['policyeval'], 'evalId': record['evalId']},
                             session=dbsession)
    if not rc:
        raise Exception("DB update failed")
    else:
        return record
