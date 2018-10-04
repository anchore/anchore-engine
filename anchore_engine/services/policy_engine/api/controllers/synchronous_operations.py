"""
Controller for all synchronous web operations. These are handled by the main web service endpoint.

Async operations are handled by teh async_operations controller.

"""

import json
import time
import hashlib
import re
import datetime

import connexion
from flask import abort, Response
from werkzeug.exceptions import HTTPException
from sqlalchemy import or_, and_


import anchore_engine.subsys.servicestatus
from anchore_engine import utils, apis
from anchore_engine.common.helpers import make_response_error

from anchore_engine.services.policy_engine.api.models import Image as ImageMsg, PolicyValidationResponse

from anchore_engine.services.policy_engine.api.models import ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport, \
    GateSpec, TriggerParamSpec, TriggerSpec
from anchore_engine.services.policy_engine.api.models import PolicyEvaluation, PolicyEvaluationProblem
from anchore_engine.db import Image, ImageCpe, CpeVulnerability, get_thread_scoped_session as get_session, ImagePackageVulnerability, CatalogImageDocker, ImageCpe,CpeVulnerability, Vulnerability, ImagePackage, NvdMetadata, db_catalog_image
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, build_empty_error_execution
from anchore_engine.services.policy_engine.engine.policy.exceptions import InitializationError
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext, Gate
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for
from anchore_engine.services.policy_engine.engine.vulnerabilities import rescan_image
from anchore_engine.db import DistroNamespace
from anchore_engine.subsys import logger as log
from anchore_engine.apis.authorization import get_authorizer, Permission


authorizer = get_authorizer()


# Leave this here to ensure gates registry is fully loaded
import anchore_engine.subsys.metrics
from anchore_engine.subsys.metrics import flask_metrics

TABLE_STYLE_HEADER_LIST = ['CVE_ID', 'Severity', '*Total_Affected', 'Vulnerable_Package', 'Fix_Available', 'Fix_Images', 'Rebuild_Images', 'URL', 'Package_Type', 'Feed', 'Feed_Group', 'Package_Name', 'Package_Version', 'CVES']

# Toggle of lock usage, primarily for testing and debugging usage
feed_sync_locking_enabled = True


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def get_status():
    """
    Generic status return common to all services
    :return:
    """
    httpcode = 500
    try:
        service_record = anchore_engine.subsys.servicestatus.get_my_service_record()
        return_object = anchore_engine.subsys.servicestatus.get_status(service_record)
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            #for pkg_vuln in img.java_vulnerabilities():
            #    db.delete(pkg_vuln)
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
@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
            # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
            if vendor_only and vuln.fix_has_no_advisory():
                continue

            cves = ''
            if vuln.vulnerability.additional_metadata:
                cves = ' '.join(vuln.vulnerability.additional_metadata.get('cves', []))

            rows.append([
                vuln.vulnerability_id,
                vuln.vulnerability.severity,
                1,
                vuln.pkg_name + '-' + vuln.package.fullversion,
                str(vuln.fixed_in()),
                vuln.pkg_image_id,
                'None', # Always empty this for now
                vuln.vulnerability.link,
                vuln.pkg_type,
                'vulnerabilities',
                vuln.vulnerability.namespace_name,
                vuln.pkg_name,
                vuln.package.fullversion,
                cves,
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

            cpe_hashes = {}
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
                    'feed_name': vulnerability_cpe.feed_name,
                    'feed_namespace': vulnerability_cpe.namespace_name,
                }
                cpe_hash = hashlib.sha256(utils.ensure_bytes(json.dumps(cpe_vuln_el))).hexdigest()
                if not cpe_hashes.get(cpe_hash, False):
                    cpe_vuln_listing.append(cpe_vuln_el)
                    cpe_hashes[cpe_hash] = True
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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


@authorizer.requires([Permission(domain='system', action='*', target='*')])
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
                    param_list = sorted(list(params.values()), key=lambda x: x.sort_order)
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

def _get_imageId_to_record(userId, dbsession=None):
    imageId_to_record = {}

    tag_re = re.compile("([^/]+)/([^:]+):(.*)")

    imagetags = db_catalog_image.get_all_tagsummary(userId, session=dbsession)
    fulltags = {}
    tag_history = {}
    for x in imagetags:
        if x['imageId'] not in tag_history:
            tag_history[x['imageId']] = []

        registry, repo, tag = tag_re.match(x['fulltag']).groups()

        if x['tag_detected_at']:
            tag_detected_at = datetime.datetime.utcfromtimestamp(float(int(x['tag_detected_at']))).isoformat() +'Z'
        else:
            tag_detected_at = 0

        tag_el = {
            'registry': registry,
            'repo': repo,
            'tag': tag,
            'fulltag': x['fulltag'],
            'tag_detected_at': tag_detected_at,
        }
        tag_history[x['imageId']].append(tag_el)

        if x['imageId'] not in imageId_to_record:
            if x['analyzed_at']:
                analyzed_at = datetime.datetime.utcfromtimestamp(float(int(x['analyzed_at']))).isoformat() +'Z'
            else:
                analyzed_at = 0

            imageId_to_record[x['imageId']] = {
                'imageDigest': x['imageDigest'],
                'imageId': x['imageId'],
                'analyzed_at': analyzed_at,
                'tag_history': tag_history[x['imageId']],
            }

    return(imageId_to_record)
        
def query_images_by_package(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    pkg_name = request_inputs.get('params', {}).get('name', None)
    pkg_version = request_inputs.get('params', {}).get('version', None)
    pkg_type = request_inputs.get('params', {}).get('package_type', None)

    ret_hash = {}
    pkg_hash = {}
    try:
        ipm_query = dbsession.query(ImagePackage).filter(ImagePackage.name==pkg_name)
        cpm_query = dbsession.query(ImageCpe).filter(ImageCpe.name==pkg_name)

        if pkg_version and pkg_version != 'None':
            ipm_query = ipm_query.filter(or_(ImagePackage.version==pkg_version, ImagePackage.fullversion==pkg_version))
            cpm_query = cpm_query.filter(ImageCpe.version==pkg_version)
        if pkg_type and pkg_type != 'None':
            ipm_query = ipm_query.filter(ImagePackage.pkg_type==pkg_type)
            cpm_query = cpm_query.filter(ImageCpe.pkg_type==pkg_type)

        image_package_matches = ipm_query
        cpe_package_matches = cpm_query

        #ipm_dbfilter = {'name': pkg_name}
        #cpm_dbfilter = {'name': pkg_name}

        #if pkg_version and pkg_version != 'None':
        #    ipm_dbfilter['version'] = pkg_version
        #    cpm_dbfilter['version'] = pkg_version
        #if pkg_type and pkg_type != 'None':
        #    ipm_dbfilter['pkg_type'] = pkg_type
        #    cpm_dbfilter['pkg_type'] = pkg_type

        #image_package_matches = dbsession.query(ImagePackage).filter_by(**ipm_dbfilter).all()
        #cpe_package_matches = dbsession.query(ImageCpe).filter_by(**cpm_dbfilter).all()

        if image_package_matches or cpe_package_matches:
            imageId_to_record = _get_imageId_to_record(userId, dbsession=dbsession)

            for image in image_package_matches:
                imageId = image.image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {'image': imageId_to_record.get(imageId, {}), 'packages': []}
                    pkg_hash[imageId] = {}

                pkg_el = {
                    'name': image.name,
                    'version': image.fullversion,
                    'type': image.pkg_type,
                }
                phash = hashlib.sha256(json.dumps(pkg_el).encode('utf-8')).hexdigest()
                if not pkg_hash[imageId].get(phash, False):
                    ret_hash[imageId]['packages'].append(pkg_el)
                pkg_hash[imageId][phash] = True

            for image in cpe_package_matches:
                imageId = image.image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {'image': imageId_to_record.get(imageId, {}), 'packages': []}
                    pkg_hash[imageId] = {}

                pkg_el = {
                    'name': image.name,
                    'version': image.version,
                    'type': image.pkg_type,
                }
                phash = hashlib.sha256(json.dumps(pkg_el).encode('utf-8')).hexdigest()
                if not pkg_hash[imageId].get(phash, False):
                    ret_hash[imageId]['packages'].append(pkg_el)
                pkg_hash[imageId][phash] = True

        matched_images = list(ret_hash.values())
        return_object = {
            'matched_images': matched_images
        }            
        httpcode = 200
    except Exception as err:
        log.error("{}".format(err))
        return_object = make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)


advisory_cache={}
def check_no_advisory(image):
    phash = hashlib.sha256(json.dumps([image.pkg_name, image.pkg_version, image.vulnerability_namespace_name]).encode('utf-8')).hexdigest()
    if phash not in advisory_cache:
        advisory_cache[phash] = image.fix_has_no_advisory()

    return(advisory_cache.get(phash))


def query_images_by_vulnerability(dbsession, request_inputs):
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = {}
    httpcode = 500

    id = request_inputs.get('params', {}).get('vulnerability_id', None)
    severity_filter = request_inputs.get('params', {}).get('severity', None)
    namespace_filter = request_inputs.get('params', {}).get('namespace', None)
    affected_package_filter = request_inputs.get('params', {}).get('affected_package', None)
    vendor_only = request_inputs.get('params', {}).get('vendor_only', True)

    ret_hash = {}
    pkg_hash = {}
    try:
        start = time.time()
        image_package_matches = []
        image_cpe_matches = []

        ipm_query = dbsession.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_id==id)
        icm_query = dbsession.query(ImageCpe,CpeVulnerability).filter(CpeVulnerability.vulnerability_id==id).filter(ImageCpe.name==CpeVulnerability.name).filter(ImageCpe.version==CpeVulnerability.version)

        if severity_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.vulnerability.has(severity=severity_filter))
            icm_query = icm_query.filter(CpeVulnerability.severity==severity_filter)
        if namespace_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.vulnerability_namespace_name==namespace_filter)
            icm_query = icm_query.filter(CpeVulnerability.namespace_name==namespace_filter)
        if affected_package_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.pkg_name==affected_package_filter)
            icm_query = icm_query.filter(ImageCpe.name==affected_package_filter)

        image_package_matches = ipm_query#.all()
        image_cpe_matches = icm_query#.all()

        log.debug("QUERY TIME: {}".format(time.time() - start))

        start = time.time()
        if image_package_matches or image_cpe_matches:
            imageId_to_record = _get_imageId_to_record(userId, dbsession=dbsession)
        
            start = time.time()
            for image in image_package_matches:
                if vendor_only and check_no_advisory(image):
                    continue

                imageId = image.pkg_image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {'image': imageId_to_record.get(imageId, {}), 'vulnerable_packages': []}
                    pkg_hash[imageId] = {}

                pkg_el = {
                    #'vulnerability_id': image.vulnerability_id,
                    'name': image.pkg_name,
                    'version': image.pkg_version,
                    'type': image.pkg_type,
                    'namespace': image.vulnerability_namespace_name,
                    'severity': image.vulnerability.severity,
                }

                ret_hash[imageId]['vulnerable_packages'].append(pkg_el)
            log.debug("IMAGEOSPKG TIME: {}".format(time.time() - start))

            start = time.time()
            for image_cpe, vulnerability_cpe in image_cpe_matches:
                imageId = image_cpe.image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {'image': imageId_to_record.get(imageId, {}), 'vulnerable_packages': []}
                    pkg_hash[imageId] = {}
                pkg_el = {
                    #'vulnerability_id': vulnerability_cpe.vulnerability_id,
                    'name': image_cpe.name,
                    'version': image_cpe.version,
                    'type': image_cpe.pkg_type,
                    'namespace': "{}".format(vulnerability_cpe.namespace_name),
                    'severity': "{}".format(vulnerability_cpe.severity),
                }
                phash = hashlib.sha256(json.dumps(pkg_el).encode('utf-8')).hexdigest()
                if not pkg_hash[imageId].get(phash, False):
                    ret_hash[imageId]['vulnerable_packages'].append(pkg_el)
                pkg_hash[imageId][phash] = True

        log.debug("IMAGECPEPKG TIME: {}".format(time.time() - start))

        start = time.time()
        vulnerable_images = list(ret_hash.values())
        return_object = {
            'vulnerable_images': vulnerable_images
        }
        log.debug("RESP TIME: {}".format(time.time() - start))
        httpcode = 200

    except Exception as err:
        log.error("{}".format(err))
        return_object = make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

def query_vulnerabilities(dbsession, request_inputs):
    user_auth = request_inputs['auth']
    method = request_inputs['method']
    params = request_inputs['params']
    userId = request_inputs['userId']

    return_object = []
    httpcode = 500

    id = request_inputs.get('params', {}).get('id', None)
    package_name_filter = request_inputs.get('params', {}).get('affected_package', None)
    package_version_filter = request_inputs.get('params', {}).get('affected_package_version', None)
    vulnerability_exists = False

    try:
        return_el_template = {
            'id': None,
            'namespace': None,
            'severity': None,
            'link': None,
            'affected_packages': None,
        }

        pn_hash = {}

        vulnerabilities = dbsession.query(NvdMetadata).filter(NvdMetadata.name==id).all()
        if vulnerabilities:
            vulnerability_exists = True
            for vulnerability in vulnerabilities:
                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el['id'] = vulnerability.name
                namespace_el['namespace'] = vulnerability.namespace_name
                namespace_el['severity'] = vulnerability.severity
                namespace_el['link'] = "https://nvd.nist.gov/vuln/detail/{}".format(vulnerability.name)
                namespace_el['affected_packages'] = []

                # TODO the package info search, and filter, add to affected_packages list
                for v_pkg in vulnerability.vulnerable_cpes:
                    if (not package_name_filter or package_name_filter == v_pkg.name) and (not package_version_filter or package_version_filter == v_pkg.version):
                        pkg_el = {
                            'name': v_pkg.name,
                            'version': v_pkg.version,
                            'type': '*',
                        }
                        namespace_el['affected_packages'].append(pkg_el)

                if not package_name_filter or (package_name_filter and namespace_el['affected_packages']):
                    return_object.append(namespace_el)

        vulnerabilities = dbsession.query(Vulnerability).filter(Vulnerability.id==id).all()
        if vulnerabilities:
            for vulnerability in vulnerabilities:
                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el['id'] = vulnerability.id
                namespace_el['namespace'] = vulnerability.namespace_name
                namespace_el['severity'] = vulnerability.severity
                namespace_el['link'] = vulnerability.link
                namespace_el['affected_packages'] = []
                
                # TODO the package info search, and filter, add to affected_packages list
                for v_pkg in vulnerability.fixed_in:
                    if (not package_name_filter or package_name_filter == v_pkg.name) and (not package_version_filter or package_version_filter == v_pkg.version):
                        pkg_el = {
                            'name': v_pkg.name,
                            'version': v_pkg.version,
                            'type': v_pkg.version_format,
                        }
                        if not v_pkg.version or v_pkg.version.lower() == 'none':
                            pkg_el['version'] = '*'

                        namespace_el['affected_packages'].append(pkg_el)

                if not package_name_filter or (package_name_filter and namespace_el['affected_packages']):
                    return_object.append(namespace_el)

        httpcode = 200
            
    except Exception as err:
        log.error("{}".format(err))
        return_object = make_response_error(err, in_httpcode=httpcode)

    return(return_object, httpcode)

@authorizer.requires([Permission(domain='system', action='*', target='*')])
def query_vulnerabilities_get(id=None, affected_package=None, affected_package_version=None):
    try:
        session = get_session()
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'id': id, 'affected_package': affected_package, 'affected_package_version': affected_package_version})
        return_object, httpcode = query_vulnerabilities(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)
    finally:
        session.close()

    return (return_object, httpcode)    

@authorizer.requires([Permission(domain='system', action='*', target='*')])
def query_images_by_package_get(user_id, name=None, version=None, package_type=None):

    try:
        session = get_session()
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'name': name, 'version': version, 'package_type': package_type})
        return_object, httpcode = query_images_by_package(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)
    finally:
        session.close()

    return (return_object, httpcode)    


@authorizer.requires([Permission(domain='system', action='*', target='*')])
def query_images_by_vulnerability_get(user_id, vulnerability_id=None, severity=None, namespace=None, affected_package=None, vendor_only=True):
    try:
        session = get_session()
        request_inputs = apis.do_request_prep(connexion.request, default_params={'vulnerability_id': vulnerability_id, 'severity': severity, 'namespace': namespace, 'affected_package': affected_package, 'vendor_only': vendor_only})
        return_object, httpcode = query_images_by_vulnerability(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)
    finally:
        session.close()

    return (return_object, httpcode)
