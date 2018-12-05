import connexion

import anchore_engine.apis
import anchore_engine.common.helpers
from anchore_engine import db
from anchore_engine.db import db_policyeval
#import catalog_impl
from anchore_engine.services.catalog import catalog_impl
import anchore_engine.common
from anchore_engine.subsys import logger, archive as archive_sys
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_evals(policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False, interactive=False):
    """
    GET /evals

    :param bodycontent:
    :return:
    """
    httpcode = 500

    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            evals = list_evals_impl(session, userId=user_id, policyId=policyId, imageDigest=imageDigest, tag=tag,evalId=evalId, interactive=interactive, newest_only=newest_only)
            if not evals:
                httpcode = 404
                raise Exception("eval not found in DB")

        return evals, 200

    except Exception as err:
        return str(anchore_engine.common.helpers.make_response_error(err, in_httpcode=httpcode)), 500

    # return (return_object, httpcode)
    #     httpcode = 500
    #     return_object = str(err)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def add_eval(bodycontent):
    """
    POST /evals
    :param bodycontent:
    :return:
    """

    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            return_object, httpcode = upsert_eval(session, userId=user_id, record=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_eval(bodycontent):
    """
    PUT /evals

    :param bodycontent:
    :return:
    """
    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
        user_id = request_inputs['userId']

        with db.session_scope() as session:
            return_object, httpcode = upsert_eval(session, userId=user_id, record=bodycontent)

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_eval(bodycontent):
    """
    DELETE /evals
    :param bodycontent:
    :return:
    """
    httpcode = 500
    try:

        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})
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


def list_evals_impl(dbsession, userId, policyId=None, imageDigest=None, tag=None, evalId=None, newest_only=False, interactive=False):
    logger.debug("looking up eval record: " + userId)

    # set up the filter based on input
    dbfilter = {}
    latest_eval_record = latest_eval_result = None

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

        latest_eval_record, latest_eval_result = catalog_impl.perform_policy_evaluation(userId, imageDigest, dbsession, evaltag=evaltag, policyId=policyId, interactive=interactive, newest_only=newest_only)
    except Exception as err:
        logger.error("interactive eval failed - exception: {}".format(err))

    records = []
    if interactive or newest_only:
        try:
            latest_eval_record['result'] = latest_eval_result
            records = [latest_eval_record]
        except:
            raise Exception("interactive or newest_only eval requested, but unable to perform eval at this time")
    else:
        records = db_policyeval.tsget_byfilter(userId, session=dbsession, **dbfilter)
        for record in records:
            try:
                result = archive_sys.get_document(userId, 'policy_evaluations', record['evalId'])
                record['result'] = result
            except:
                record['result'] = {}

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
