import json

import connexion

from anchore_engine.apis.authorization import get_authorizer, Permission, RequestingAccountValue
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services import internal_client_for
import anchore_engine.configuration.localconfig
import anchore_engine.subsys.servicestatus
import anchore_engine.subsys.metrics
import anchore_engine.common
from anchore_engine.subsys import logger
from anchore_engine.subsys.identities import manager_factory
from anchore_engine.db import session_scope


authorizer = get_authorizer()


@authorizer.requires([])
def status():
    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
        httpcode = 200
    except Exception as err:
        return_object = str(err)
        httpcode = 500

    return(return_object, httpcode)


@authorizer.requires([Permission(domain=RequestingAccountValue(), action='getImageEvaluation', target='*')])
def imagepolicywebhook(bodycontent):

    # TODO - while the image policy webhook feature is in k8s beta, we've decided to make any errors that occur during check still respond with 'allowed: True'.  This should be reverted to default to 'False' on any error, once the k8s feature is further along

    return_object = {
        "apiVersion": "imagepolicy.k8s.io/v1alpha1",
        "kind": "ImageReview",
        "status": {
            "allowed": True,
            "reason": "all images passed anchore policy evaluation"
        }
    }
    httpcode = 200

    try:
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={})

        user_auth = request_inputs['auth']
        method = request_inputs['method']
        params = request_inputs['params']
        userId = request_inputs['userId']

        try:

            final_allowed = True
            reason = "unset"

            try:
                try:
                    #incoming = json.loads(bodycontent)
                    incoming = bodycontent
                    logger.debug("incoming post data: " + json.dumps(incoming, indent=4))
                except Exception as err:
                    raise Exception("could not load post data as json: " + str(err))

                try:
                    requestUserId = None
                    requestPolicyId = None
                    # see if the request from k8s contains an anchore policy and/or whitelist name
                    if 'annotations' in incoming['spec']:
                        logger.debug("incoming request contains annotations: " + json.dumps(incoming['spec']['annotations'], indent=4))
                        requestUserId = incoming['spec']['annotations'].pop("anchore.image-policy.k8s.io/account", None)
                        if requestUserId is None:
                            requestUserId = incoming['spec']['annotations'].pop("anchore.image-policy.k8s.io/userId", None)

                        requestPolicyId = incoming['spec']['annotations'].pop("anchore.image-policy.k8s.io/policyBundleId", None)
                except Exception as err:
                    raise Exception("could not parse out annotations: " + str(err))

                if not requestUserId:
                    raise Exception("need to specify an anchore.image-policy.k8s.io/userId annotation with a valid anchore service username as a value")

                catalog = internal_client_for(CatalogClient, requestUserId)

                reason = "all images passed anchore policy checks"
                final_action = False
                for el in incoming['spec']['containers']:
                    image = el['image']
                    logger.debug("found image in request: " + str(image))
                    image_records = catalog.get_image(tag=image)
                    if not image_records:
                        raise Exception("could not find requested image ("+str(image)+") in anchore service DB")

                    for image_record in image_records:
                        imageDigest = image_record['imageDigest']

                        for image_detail in image_record['image_detail']:
                            fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ':' + image_detail['tag']
                            result = catalog.get_eval_latest(tag=fulltag, imageDigest=imageDigest, policyId=requestPolicyId)
                            if result:
                                httpcode = 200
                                if result['final_action'].upper() not in ['GO', 'WARN']:
                                    final_action = False
                                    raise Exception("image failed anchore policy check: " + json.dumps(result, indent=4))
                                else:
                                    final_action = True
                                    
                            else:
                                httpcode = 404
                                final_action = False
                                raise Exception("no anchore evaluation available for image: " + str(image))

                final_allowed = final_action

            except Exception as err:
                reason = str(err)
                final_allowed = False
                httpcode = 200

            return_object['status']['allowed'] = final_allowed
            return_object['status']['reason'] = reason

            anchore_engine.subsys.metrics.counter_inc("anchore_image_policy_webhooks_evaluation_total", allowed=final_allowed)

            #logger.debug("final return: " + json.dumps(return_object, indent=4))
            httpcode = 200
        except Exception as err:
            return_object['reason'] = str(err)
            httpcode = 500

    except Exception as err:
        return_object['reason'] = str(err)
        httpcode = 500

    return(return_object, httpcode)
