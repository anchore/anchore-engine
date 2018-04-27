"""
Controller for all synchronous web operations. These are handled by the main web service endpoint.

Async operations are handled by teh async_operations controller.

"""

import json
import time

import connexion
from flask import abort, Response
from werkzeug.exceptions import HTTPException

import anchore_engine.subsys.servicestatus
from anchore_engine.services.policy_engine.api.models import Image as ImageMsg, PolicyValidationResponse

from anchore_engine.services.policy_engine.api.models import ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport, \
    GateSpec, TriggerParamSpec, TriggerSpec
from anchore_engine.services.policy_engine.api.models import PolicyEvaluation, PolicyEvaluationProblem
from anchore_engine.db import Image, ImageCpe, CpeVulnerability, get_thread_scoped_session as get_session
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, build_empty_error_execution
from anchore_engine.services.policy_engine.engine.policy.exceptions import InitializationError
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext, Gate
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.services.policy_engine.engine.vulnerabilities import rescan_image
from anchore_engine.db import DistroNamespace
from anchore_engine.subsys import logger as log

# Leave this here to ensure gates registry is fully loaded
import anchore_engine.subsys.metrics
from anchore_engine.subsys.metrics import flask_metrics

TABLE_STYLE_HEADER_LIST = ['CVE_ID', 'Severity', '*Total_Affected', 'Vulnerable_Package', 'Fix_Available', 'Fix_Images', 'Rebuild_Images', 'URL']

# Toggle of lock usage, primarily for testing and debugging usage
feed_sync_locking_enabled = True


def get_status():
    """
    Generic status return common to all services
    :return:
    """
    httpcode = 500
    try:
        localconfig = anchore_engine.configuration.localconfig.get_config()
        return_object = anchore_engine.subsys.servicestatus.get_status({'hostid': localconfig['host_id'], 'servicename': 'policy_engine'})
        #return_object = {
        #    'busy': False,
        #    'up': True,
        #    'message': 'all good'
        #}
        httpcode = 200
    except Exception as err:
        return_object = str(err)

    return (return_object, httpcode)


class ImageMessageMapper(object):
    """
    Map the msg to db and vice-versa
    """
    rfc2339_date_fmt = '%Y-%m-%dT%H:%M:%SZ'

    def db_to_msg(self, db_obj):
        msg = ImageMsg()
        msg.last_modified = db_obj.last_modified.strftime(self.rfc2339_date_fmt)
        msg.created_at = db_obj.created_at.strftime(self.rfc2339_date_fmt)
        msg.distro_namespace = db_obj.distro_namespace
        msg.user_id = db_obj.user_id
        msg.state = db_obj.state
        msg.id = db_obj.id
        msg.digest = db_obj.digest
        msg.tags = []
        return msg

    def msg_to_db(self, msg):
        db_obj = Image()
        db_obj.id = msg.id
        db_obj.digest = msg.digest
        db_obj.user_id = msg.user_id
        db_obj.created_at = msg.created_at
        db_obj.last_modified = msg.last_modified
        return db_obj

msg_mapper = ImageMessageMapper()


def list_image_users(page=None):
    """
    Returns the list of users the system knows about, based on images from users.
    Queries the set of users in the images list.

    :return: List of user_id strings
    """
    db = get_session()
    if not db:
        db = get_session()
    try:
        users = db.query(Image.user_id).group_by(Image.user_id).all()
        img_user_set = set([rec[0] for rec in users])
    finally:
        db.close()

    return list(img_user_set)


def list_user_images(user_id):
    """
    Given a user_id, returns a list of Image objects scoped to that user.

    :param user_id: str user identifier
    :return: List of Image (messsage) objects
    """
    db = get_session()
    try:
        imgs = [msg_mapper.db_to_msg(i).to_dict() for i in db.query(Image).filter(Image.user_id == user_id).all()]
    finally:
        db.close()

    return imgs

@flask_metrics.do_not_track()
def delete_image(user_id, image_id):
    """
    DELETE the image and all resources for it. Returns 204 - No Content on success

    :param user_id:
    :param image_id:
    :return:
    """
    db = get_session()
    try:
        log.info('Deleting image {}/{} and all associated resources'.format(user_id, image_id))
        img = db.query(Image).get((image_id, user_id))
        if img:
            for pkg_vuln in img.vulnerabilities():
                db.delete(pkg_vuln)
            db.delete(img)
            db.commit()
        else:
            db.rollback()

        # Idempotently return 204. This isn't properly RESTY, but idempotency on delete makes clients much cleaner.
        return (None, 204)
    except HTTPException:
        raise
    except Exception:
        log.exception('Error processing DELETE request for image {}/{}'.format(user_id, image_id))
        db.rollback()
        abort(500)


def problem_from_exception(eval_exception, severity=None):
    """
    Constructs a messaging-layer PolicyEvaluationProblem from the given exception instance.

    :param eval_exception:
    :return: an initialized PolicyEvaluationProblem
    """
    if not eval_exception:
        return None

    prob = PolicyEvaluationProblem()

    # If there is a details() function, call that
    if hasattr(eval_exception, 'details') and callable(eval_exception.details):
        prob.details = eval_exception.details()
    else:
        prob.details = eval_exception.message

    prob.problem_type = eval_exception.__class__.__name__
    if hasattr(eval_exception, 'severity') and eval_exception.severity:
        prob.severity = eval_exception.severity
    elif severity:
        prob.severity = severity
    else:
        prob.severity = 'error'
    return prob


@flask_metrics.do_not_track()
def check_user_image_inline(user_id, image_id, tag, bundle):
    """
    Execute a policy evaluation using the info in the request body including the bundle content

    :param user_id:
    :param image_id:
    :param tag:
    :param bundle:
    :return:
    """

    timer = time.time()
    db = get_session()
    try:
        # Input validation
        if tag is None:
            # set tag value to a value that only matches wildcards
            tag = '*/*:*'

        try:
            img_obj = db.query(Image).get((image_id, user_id))
        except:
            abort(Response(response='Image not found', status=404))

        if not img_obj:
            log.info('Request for evaluation of image that cannot be found: user_id = {}, image_id = {}'.format(user_id, image_id))
            abort(Response(response='Image not found', status=404))

        # Build bundle exec.
        problems = []
        executable_bundle = None
        try:
            # Allow deprecated gates here to support upgrade cases from old policy bundles.
            executable_bundle = build_bundle(bundle, for_tag=tag, allow_deprecated=True)
            if executable_bundle.init_errors:
                problems = executable_bundle.init_errors
        except InitializationError as e:
            log.exception('Bundle construction and initialization returned errors')
            problems = e.causes

        eval_result = None
        if not problems:
            # Execute bundle
            try:
                eval_result = executable_bundle.execute(img_obj, tag, ExecutionContext(db_session=db, configuration={}))
            except Exception as e:
                log.exception('Error executing policy bundle {} against image {} w/tag {}: {}'.format(bundle['id'], image_id, tag, e.message))
                abort(Response(response='Cannot execute given policy against the image due to errors executing the policy bundle: {}'.format(e.message), status=500))
        else:
            # Construct a failure eval with details on the errors and mappings to send to client
            eval_result = build_empty_error_execution(img_obj, tag, executable_bundle, errors=problems, warnings=[])
            if executable_bundle and executable_bundle.mapping and len(executable_bundle.mapping.mapping_rules) == 1:
                eval_result.executed_mapping = executable_bundle.mapping.mapping_rules[0]

        resp = PolicyEvaluation()
        resp.user_id = user_id
        resp.image_id = image_id
        resp.tag = tag
        resp.bundle = bundle
        resp.matched_mapping_rule = eval_result.executed_mapping.json() if eval_result.executed_mapping else False
        resp.last_modified = int(time.time())
        resp.final_action = eval_result.bundle_decision.final_decision.name
        resp.final_action_reason = eval_result.bundle_decision.reason
        resp.matched_whitelisted_images_rule = eval_result.bundle_decision.whitelisted_image.json() if eval_result.bundle_decision.whitelisted_image else False
        resp.matched_blacklisted_images_rule = eval_result.bundle_decision.blacklisted_image.json() if eval_result.bundle_decision.blacklisted_image else False
        resp.result = eval_result.as_table_json()
        resp.created_at = int(time.time())
        resp.evaluation_problems = [problem_from_exception(i) for i in eval_result.errors]
        resp.evaluation_problems += [problem_from_exception(i) for i in eval_result.warnings]
        if resp.evaluation_problems:
            for i in resp.evaluation_problems:
                log.warn('Returning evaluation response for image {}/{} w/tag {} and bundle {} that contains error: {}'.format(user_id, image_id, tag, bundle['id'], json.dumps(i.to_dict())))
            anchore_engine.subsys.metrics.histogram_observe('anchore_policy_evaluation_time_seconds', time.time() - timer, status="fail")
        else:
            anchore_engine.subsys.metrics.histogram_observe('anchore_policy_evaluation_time_seconds', time.time() - timer, status="success")

        return resp.to_dict()

    except HTTPException as e:
        db.rollback()
        log.exception('Caught exception in execution: {}'.format(e))
        raise
    except Exception as e:
        db.rollback()
        log.exception('Failed processing bundle evaluation: {}'.format(e))
        abort(Response('Unexpected internal error', 500))
    finally:
        db.close()


@flask_metrics.do_not_track()
def get_image_vulnerabilities(user_id, image_id, force_refresh=False, vendor_only=True):
    """
    Return the vulnerability listing for the specified image and load from catalog if not found and specifically asked
    to do so.


    Example json output:
    {
       "multi" : {
          "url_column_index" : 7,
          "result" : {
             "rows" : [],
             "rowcount" : 0,
             "colcount" : 8,
             "header" : [
                "CVE_ID",
                "Severity",
                "*Total_Affected",
                "Vulnerable_Package",
                "Fix_Available",
                "Fix_Images",
                "Rebuild_Images",
                "URL"
             ]
          },
          "querycommand" : "/usr/lib/python2.7/site-packages/anchore/anchore-modules/multi-queries/cve-scan.py /ebs_data/anchore/querytmp/queryimages.7026386 /ebs_data/anchore/data /ebs_data/anchore/querytmp/query.59057288 all",
          "queryparams" : "all",
          "warns" : [
             "0005b136f0fb (prom/prometheus:master) cannot perform CVE scan: no CVE data is currently available for the detected base distro type (busybox:unknown_version,busybox:v1.26.2)"
          ]
       }
    }

    :param user_id: user id of image to evaluate
    :param image_id: image id to evaluate
    :param force_refresh: if true, flush and recompute vulnerabilities rather than returning current values
    :param vendor_only: if true, filter out the vulnerabilities that vendors will explicitly not address
    :return:
    """

    # Has image?
    db = get_session()
    try:
        img = db.query(Image).get((image_id, user_id))
        vulns = []
        if not img:
            abort(404)
        else:
            if force_refresh:
                log.info('Forcing refresh of vulnerabiltiies for {}/{}'.format(user_id, image_id))
                try:
                    vulns = rescan_image(img, db_session=db)
                    db.commit()
                except Exception as e:
                    log.exception('Error refreshing cve matches for image {}/{}'.format(user_id, image_id))
                    db.rollback()
                    abort(Response('Error refreshing vulnerability listing for image.', 500))

                db = get_session()
                db.refresh(img)
            
            vulns = img.vulnerabilities()

        # Has vulnerabilities?
        warns = []
        if not vulns:
            vulns = []
            ns = DistroNamespace.for_obj(img)
            if not have_vulnerabilities_for(ns):
                warns = ['No vulnerability data available for image distro: {}'.format(ns.namespace_name)]


        rows = []
        for vuln in vulns:
            # if vuln.vulnerability.fixed_in:
            #     fixes_in = filter(lambda x: x.name == vuln.pkg_name or x.name == vuln.package.normalized_src_pkg,
            #            vuln.vulnerability.fixed_in)
            #     fix_available_in = fixes_in[0].version if fixes_in else 'None'
            # else:
            #     fix_available_in = 'None'

            # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
            if vendor_only and vuln.fix_has_no_advisory():
                continue

            rows.append([
                vuln.vulnerability_id,
                vuln.vulnerability.severity,
                1,
                vuln.pkg_name + '-' + vuln.package.fullversion,
                str(vuln.fixed_in()),
                vuln.pkg_image_id,
                'None', # Always empty this for now
                vuln.vulnerability.link
                ]
            )

        vuln_listing = {
            'multi': {
                'url_column_index': 7,
                'result': {
                    'header': TABLE_STYLE_HEADER_LIST,
                    'rowcount': len(rows),
                    'colcount': len(TABLE_STYLE_HEADER_LIST),
                    'rows': rows
                },
                'warns': warns
            }
        }

        cpe_vuln_listing = []
        try:
            all_cpe_matches = db.query(ImageCpe,CpeVulnerability).filter(ImageCpe.image_id==image_id).filter(ImageCpe.name==CpeVulnerability.name).filter(ImageCpe.version==CpeVulnerability.version)
            if not all_cpe_matches:
                all_cpe_matches = []

            for image_cpe, vulnerability_cpe in all_cpe_matches:
                cpe_vuln_el = {
                    'vulnerability_id': vulnerability_cpe.vulnerability_id,
                    'severity': vulnerability_cpe.severity,
                    'link': vulnerability_cpe.link,
                    'pkg_type': image_cpe.pkg_type,
                    'pkg_path': image_cpe.pkg_path,
                    'name': image_cpe.name,
                    'version': image_cpe.version,
                    'cpe': image_cpe.get_cpestring(),
                }
                cpe_vuln_listing.append(cpe_vuln_el)
        except Exception as err:
            log.warn("could not fetch CPE matches - exception: " + str(err))

        report = LegacyVulnerabilityReport.from_dict(vuln_listing)
        resp = ImageVulnerabilityListing(user_id=user_id, image_id=image_id, legacy_report=report, cpe_report=cpe_vuln_listing)
        return resp.to_dict()
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        log.exception('Error checking image {}, {} for vulnerabiltiies. Rolling back'.format(user_id, image_id))
        db.rollback()
        abort(500)
    finally:
        db.close()


def ingress_image(ingress_request):
    """
    :param ingress_request json object specifying the identity of the image to sync
    :return: status result for image load
    """
    if not connexion.request.is_json:
        abort(400)

    req = ImageIngressRequest.from_dict(ingress_request)
    try:
        # Try this synchronously for now to see how slow it really is
        t = ImageLoadTask(req.user_id, req.image_id, url=req.fetch_url)
        result = t.execute()
        resp = ImageIngressResponse()
        if not result:
            resp.status = 'loaded'
        else:
            # We're doing a sync call above, so just send loaded. It should be 'accepted' once async works.
            resp.status = 'loaded'
        return resp.to_dict(), 200
    except Exception as e:
        abort(500, 'Internal error processing image analysis import')


def validate_bundle(policy_bundle):
    """
    Performs a validation of the given policy bundle and either returns 200 OK with a status message in the response indicating pass/fail and any validation errors.

    :param policy_bundle:
    :return: 200 OK with policy validation response
    """

    try:
        resp = PolicyValidationResponse()
        problems = []
        try:
            executable_bundle = build_bundle(policy_bundle, allow_deprecated=False)
            if executable_bundle.init_errors:
                problems = executable_bundle.init_errors
        except InitializationError as e:
            # Expand any validation issues
            problems = e.causes

        resp.valid = (len(problems) == 0)
        resp.validation_details = [problem_from_exception(i, severity='error') for i in problems]
        return resp.to_dict()

    except HTTPException as e:
        log.exception('Caught exception in execution: {}'.format(e))
        raise
    except Exception as e:
        log.exception('Failed processing bundle evaluation: {}'.format(e))
        abort(Response('Unexpected internal error', 500))


def describe_policy():
    """
    Return a dictionary/json description of the set of gates available and triggers.

    :param gate_filter: a list of gate names to filter by, if None, then all are returned
    :return: dict/json description of the gates and triggers
    """

    try:

        doc = []
        for name in Gate.registered_gate_names():
            v = Gate.get_gate_by_name(name)
            g = GateSpec()
            g.name = name
            g.description = v.__description__ if v.__description__ else ''
            g.triggers = []
            if hasattr(v, '__superceded_by__'):
                g.superceded_by = v.__superceded_by__
            else:
                g.superceded_by = None

            if hasattr(v, '__lifecycle_state__'):
                g.state = v.__lifecycle_state__.name
            else:
                g.state = 'active'

            for t in v.__triggers__:
                tr = TriggerSpec()
                tr.name = t.__trigger_name__
                tr.description = t.__description__ if t.__description__ else ''
                tr.parameters = []
                if hasattr(t, '__superceded_by__'):
                    tr.superceded_by = t.__superceded_by__
                else:
                    tr.superceded_by = None
                if hasattr(t, '__lifecycle_state__'):
                    tr.state = t.__lifecycle_state__.name
                else:
                    tr.state = 'active'

                params = t._parameters()
                if params:
                    param_list = sorted(params.values(), key=lambda x: x.sort_order)
                    for param in param_list:
                        tps = TriggerParamSpec()
                        tps.name = param.name
                        tps.description = param.description
                        tps.example = param.example
                        tps.validator = param.validator.json()
                        tps.required = param.required
                        if hasattr(param, '__superceded_by__'):
                            tps.superceded_by = param.__superceded_by__
                        else:
                            tps.superceded_by = None

                        if hasattr(param, '__lifecycle_state__'):
                            tps.state = param.__lifecycle_state__.name
                        else:
                            tps.state = 'active'

                        tr.parameters.append(tps)

                g.triggers.append(tr)

            doc.append(g.to_dict())

            doc = sorted(doc, key=lambda x: x['state'])

        return doc, 200

    except Exception as e:
        log.exception('Error describing gate system')
        abort(500, 'Internal error describing gate configuration')
