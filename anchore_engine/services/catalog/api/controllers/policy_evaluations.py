import connexion

import anchore_engine.apis
import anchore_engine.common
import anchore_engine.common.helpers
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
from anchore_engine import db
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer

# import catalog_impl
from anchore_engine.services.catalog import catalog_impl

authorizer = get_authorizer()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_evals(
    policyId=None,
    imageDigest=None,
    tag=None,
    evalId=None,
    newest_only=False,
    interactive=False,
):
    """
    GET /evals

    :param bodycontent:
    :return:
    """
    httpcode = 500

    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            connexion.request, default_params={}
        )
        user_id = request_inputs["userId"]

        with db.session_scope() as session:
            evals = catalog_impl.list_evals_impl(
                session,
                userId=user_id,
                policyId=policyId,
                imageDigest=imageDigest,
                tag=tag,
                evalId=evalId,
                interactive=interactive,
                newest_only=newest_only,
            )
            if not evals:
                httpcode = 404
                raise Exception("eval not found in DB")

        return evals, 200

    except Exception as err:
        return (
            str(
                anchore_engine.common.helpers.make_response_error(
                    err, in_httpcode=httpcode
                )
            ),
            500,
        )

    # return return_object, httpcode
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
        request_inputs = anchore_engine.apis.do_request_prep(
            connexion.request, default_params={}
        )
        user_id = request_inputs["userId"]

        with db.session_scope() as session:
            return_object, httpcode = catalog_impl.upsert_eval(
                session, userId=user_id, record=bodycontent
            )

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def update_eval(bodycontent):
    """
    PUT /evals

    :param bodycontent:
    :return:
    """
    try:
        request_inputs = anchore_engine.apis.do_request_prep(
            connexion.request, default_params={}
        )
        user_id = request_inputs["userId"]

        with db.session_scope() as session:
            return_object, httpcode = catalog_impl.upsert_eval(
                session, userId=user_id, record=bodycontent
            )

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def delete_eval(bodycontent):
    """
    DELETE /evals
    :param bodycontent:
    :return:
    """
    httpcode = 500

    try:

        request_inputs = anchore_engine.apis.do_request_prep(
            connexion.request, default_params={}
        )
        user_id = request_inputs["userId"]
        policyId = imageDigest = tag = evalId = None

        if bodycontent:
            policyId = bodycontent.get("policyId")
            imageDigest = bodycontent.get("imageDigest")
            tag = bodycontent.get("tag")
            evalId = bodycontent.get("evalId")

        with db.session_scope() as session:
            return_object = catalog_impl.delete_evals_impl(
                session,
                userId=user_id,
                policyId=policyId,
                imageDigest=imageDigest,
                tag=tag,
                evalId=evalId,
            )
            if return_object:
                httpcode = 200
            else:
                httpcode = 500
                raise Exception(
                    "Error processing policy evaluation deletion with content: {}".format(
                        bodycontent
                    )
                )

    except Exception as err:
        httpcode = 500
        return_object = str(err)

    return return_object, httpcode
