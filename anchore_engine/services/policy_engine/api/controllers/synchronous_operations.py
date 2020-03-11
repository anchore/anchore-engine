"""
Controller for all synchronous web operations. These are handled by the main web service endpoint.

Async operations are handled by teh async_operations controller.

"""
import base64
import connexion
import datetime
import enum
import json
import time
import hashlib
import os
import re
from sqlalchemy import or_, asc, func, orm
from werkzeug.exceptions import HTTPException


import anchore_engine.subsys.servicestatus
from anchore_engine import utils, apis
from anchore_engine.common.helpers import make_response_error

from anchore_engine.services.policy_engine.api.models import Image as ImageMsg, PolicyValidationResponse

from anchore_engine.services.policy_engine.api.models import ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport, \
    GateSpec, TriggerParamSpec, TriggerSpec
from anchore_engine.services.policy_engine.api.models import PolicyEvaluation, PolicyEvaluationProblem
from anchore_engine.db import Image, get_thread_scoped_session as get_session, ImagePackageVulnerability, ImageCpe, Vulnerability, ImagePackage, db_catalog_image, CachedPolicyEvaluation, select_nvd_classes, VulnDBMetadata, VulnDBCpe
from anchore_engine.services.policy_engine.engine.policy.bundles import build_bundle, build_empty_error_execution
from anchore_engine.services.policy_engine.engine.policy.exceptions import InitializationError
from anchore_engine.services.policy_engine.engine.policy.gate import ExecutionContext, Gate
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.services.policy_engine.engine.vulnerabilities import have_vulnerabilities_for, merge_nvd_metadata, merge_nvd_metadata_image_packages
from anchore_engine.services.policy_engine.engine.vulnerabilities import rescan_image
from anchore_engine.db import DistroNamespace, AnalysisArtifact
from anchore_engine.subsys import logger as log
from anchore_engine.apis.authorization import get_authorizer, INTERNAL_SERVICE_ALLOWED
from anchore_engine.services.policy_engine.engine.feeds.db import get_all_feeds
from anchore_engine.clients.services import internal_client_for, catalog
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.utils import ensure_str, ensure_bytes

authorizer = get_authorizer()

# Leave this here to ensure gates registry is fully loaded
from anchore_engine.subsys import metrics
from anchore_engine.subsys.metrics import flask_metrics

TABLE_STYLE_HEADER_LIST = ['CVE_ID', 'Severity', '*Total_Affected', 'Vulnerable_Package', 'Fix_Available', 'Fix_Images', 'Rebuild_Images', 'URL', 'Package_Type', 'Feed', 'Feed_Group', 'Package_Name', 'Package_Version', 'CVES']

DEFAULT_CACHE_CONN_TIMEOUT = -1 # Disabled by default, can be set in config file. Seconds for connection to cache for policy evals
DEFAULT_CACHE_READ_TIMEOUT = -1 # Disabled by default, can be set in config file. Seconds for first byte timeout for policy eval cache

# Toggle of lock usage, primarily for testing and debugging usage
feed_sync_locking_enabled = True

evaluation_cache_enabled = (os.getenv('ANCHORE_POLICY_ENGINE_EVALUATION_CACHE_ENABLED', 'true').lower() == 'true')

def get_api_endpoint():
    try:
        return get_service_endpoint('apiext').strip('/')
    except:
        log.warn("Could not find valid apiext endpoint for links so will use policy engine endpoint instead")
        try:
            return get_service_endpoint('policy_engine').strip('/')
        except:
            log.warn('No policy engine endpoint found either, using default but invalid url')
            return 'http://<valid endpoint not found>'

    return ''

@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
    rfc3339_date_fmt = '%Y-%m-%dT%H:%M:%SZ'

    def db_to_msg(self, db_obj):
        msg = ImageMsg()
        msg.last_modified = db_obj.last_modified.strftime(self.rfc3339_date_fmt)
        msg.created_at = db_obj.created_at.strftime(self.rfc3339_date_fmt)
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


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_cache_status():
    return {"enabled": evaluation_cache_enabled}, 200


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def set_cache_status(status):
    global evaluation_cache_enabled

    if status.get('enabled') is not None and type(status.get('enabled')) == bool:
        evaluation_cache_enabled = status.get('enabled')
        return {"enabled": evaluation_cache_enabled}, 200
    else:
        return make_response_error(errmsg='Invalid request', in_httpcode=400), 400


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
            try:
                conn_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_conn_timeout', DEFAULT_CACHE_CONN_TIMEOUT)
                read_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_read_timeout', DEFAULT_CACHE_READ_TIMEOUT)
                mgr = EvaluationCacheManager(img, None, None, conn_timeout, read_timeout)
                mgr.flush()
            except Exception as ex:
                log.exception("Could not delete evaluations for image {}/{} in the cache. May be orphaned".format(user_id, image_id))

            db.delete(img)
            db.commit()
        else:
            db.rollback()

        # Idempotently return 204. This isn't properly RESTY, but idempotency on delete makes clients much cleaner.
        return (None, 204)
    except HTTPException:
        raise
    except Exception as e:
        log.exception('Error processing DELETE request for image {}/{}'.format(user_id, image_id))
        db.rollback()
        return make_response_error('Error deleting image {}/{}: {}'.format(user_id, image_id, e), in_httpcode=500), 500


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


# Global cache for policy evaluations
class EvaluationCacheManager(object):

    class CacheStatus(enum.Enum):
        valid = 'valid'  # The cached entry is a valid result
        stale = 'stale'  # The entry is stale because a feed sync has occurred since last evaluation
        invalid = 'invalid'  # The entry is invalid because the bundle digest has changed
        missing = 'missing'  # No entry

    __cache_bucket__ = 'policy-engine-evaluation-cache'

    def __init__(self, image_object, tag, bundle, storage_conn_timeout=-1, storage_read_timeout=-1):
        self.image = image_object
        self.tag = tag
        if bundle:
            self.bundle = bundle
            self.bundle_id = None

            if bundle.get('id') is None:
                raise ValueError('Invalid bundle format')
            else:
                self.bundle_id = bundle['id']

            self.bundle_digest = self._digest_for_bundle()
        else:
            self.bundle = None
            self.bundle_id = None
            self.bundle_digest = None

        self._catalog_client = internal_client_for(catalog.CatalogClient, userId=self.image.user_id)
        self._default_catalog_conn_timeout = storage_conn_timeout
        self._default_catalog_read_timeout = storage_read_timeout

    def _digest_for_bundle(self):
        return hashlib.sha256(utils.ensure_bytes(json.dumps(self.bundle, sort_keys=True))).hexdigest()

    def refresh(self):
        """
        Refreshes the cache state (not entry) for this initialized request.

        Has stateful side-effects of flushing objects from cache if determined to be invalid

        If a valid entry exists, it is loaded, if an invalid entry exists it is deleted

        :return:
        """
        session = get_session()
        match = None
        for result in self._lookup():
            if self._should_evaluate(result) != EvaluationCacheManager.CacheStatus.valid:
                self._delete_entry(result)
            else:
                match = result

        session.flush()

        if match:
            if match.is_archive_ref():
                bucket, key = match.archive_tuple()
                try:
                    with self._catalog_client.timeout_context(self._default_catalog_conn_timeout, self._default_catalog_read_timeout) as timeout_client:
                        data = timeout_client.get_document(bucket, key)
                except:
                    log.exception('Unexpected error getting document {}/{} from archive'.format(bucket, key))
                    data = None
            else:
                data = match.result.get('result')
        else:
            data = None

        return data

    def _delete_entry(self, entry):
        session = get_session()

        if entry.is_archive_ref():
            bucket, key = entry.archive_tuple()
            retry = 3
            while retry > 0:
                try:
                    with self._catalog_client.timeout_context(self._default_catalog_conn_timeout, self._default_catalog_read_timeout) as timeout_client:
                        resp = timeout_client.delete_document(bucket, key)
                    break
                except:
                    log.exception('Could not delete policy eval from cache, will retry. Bucket={}, Key={}'.format(bucket, key))
                    retry -= 1
            else:
                log.error('Could not flush policy eval from cache after all retries, may be orphaned. Will remove from index.')

        session.delete(entry)
        session.flush()

    def _lookup(self):
        """
        Returns all entries for the bundle,
        :param user_id:
        :param image_id:
        :param tag:
        :param bundle_id:
        :return:
        """

        session = get_session()
        return session.query(CachedPolicyEvaluation).filter_by(user_id=self.image.user_id, image_id=self.image.id, eval_tag=self.tag, bundle_id=self.bundle_id).all()

    def save(self, result):
        """
        Persist the new result for this cache entry
        :param result:
        :return:
        """
        eval = CachedPolicyEvaluation()
        eval.user_id = self.image.user_id
        eval.image_id = self.image.id
        eval.bundle_id = self.bundle_id
        eval.bundle_digest = self.bundle_digest
        eval.eval_tag = self.tag

        # Send to archive
        key = 'sha256:' + hashlib.sha256(utils.ensure_bytes(str(eval.key_tuple()))).hexdigest()
        with self._catalog_client.timeout_context(self._default_catalog_conn_timeout, self._default_catalog_read_timeout) as timeout_client:
            resp = timeout_client.put_document(self.__cache_bucket__, key, result)

        if not resp:
            raise Exception('Failed cache write to archive store')

        str_result = json.dumps(result, sort_keys=True)
        result_digest = 'sha256:' + hashlib.sha256(utils.ensure_bytes(str_result)).hexdigest()

        eval.add_remote_result(self.__cache_bucket__, key, result_digest)
        eval.last_modified = datetime.datetime.utcnow()

        # Update index
        session = get_session()
        return session.merge(eval)

    def _inputs_changed(self, cache_timestamp):
        # A feed sync has occurred since the eval was done or the image has been updated/reloaded, so inputs can have changed. Must be stale
        db = get_session()
        # TODO: zhill - test more
        feed_group_updated_list = [group.last_sync if group.last_sync is not None else datetime.datetime.utcfromtimestamp(0) for feed in get_all_feeds(db) for group in feed.groups]
        feed_synced = max(feed_group_updated_list) > cache_timestamp if feed_group_updated_list else False

        image_updated = self.image.last_modified > cache_timestamp

        return feed_synced or image_updated

    def _should_evaluate(self, cache_entry: CachedPolicyEvaluation):
        if cache_entry is None:
            metrics.counter_inc(name='anchore_policy_evaluation_cache_misses_notfound')
            return EvaluationCacheManager.CacheStatus.missing

        # The cached result is not for this exact bundle content, so result is invalid
        if cache_entry.bundle_id != self.bundle_id:
            log.warn("Unexpectedly got a cached evaluation for a different bundle id")
            metrics.counter_inc(name='anchore_policy_evaluation_cache_misses_notfound')
            return EvaluationCacheManager.CacheStatus.missing

        if cache_entry.bundle_digest == self.bundle_digest:
            # A feed sync has occurred since the eval was done or the image has been updated/reloaded, so inputs can have changed. Must be stale
            if self._inputs_changed(cache_entry.last_modified):
                metrics.counter_inc(name='anchore_policy_evaluation_cache_misses_stale')
                return EvaluationCacheManager.CacheStatus.stale
            else:
                return EvaluationCacheManager.CacheStatus.valid
        else:
            metrics.counter_inc(name='anchore_policy_evaluation_cache_misses_invalid')
            return EvaluationCacheManager.CacheStatus.invalid

    def flush(self):
        """
        Flush all cache entries for the given image
        :return:
        """
        session = get_session()
        for entry in session.query(CachedPolicyEvaluation).filter_by(user_id=self.image.user_id, image_id=self.image.id):
            try:
                self._delete_entry(entry)

            except:
                log.exception('Could not delete eval cache entry: {}'.format(entry))

        return True


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
    cache_mgr = None

    try:
        # Input validation
        if tag is None:
            # set tag value to a value that only matches wildcards
            tag = '*/*:*'

        try:
            img_obj = db.query(Image).get((image_id, user_id))
        except:
            return make_response_error('Image not found', in_httpcode=404), 404

        if not img_obj:
            log.info('Request for evaluation of image that cannot be found: user_id = {}, image_id = {}'.format(user_id, image_id))
            return make_response_error('Image not found', in_httpcode=404), 404

        if evaluation_cache_enabled:
            timer2 = time.time()
            try:
                try:
                    conn_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_conn_timeout', DEFAULT_CACHE_CONN_TIMEOUT)
                    read_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_read_timeout', DEFAULT_CACHE_READ_TIMEOUT)
                    cache_mgr = EvaluationCacheManager(img_obj, tag, bundle, conn_timeout, read_timeout)
                except ValueError as err:
                    log.warn('Could not leverage cache due to error in bundle data: {}'.format(err))
                    cache_mgr = None

                if cache_mgr is None:
                    log.info('Could not initialize cache manager for policy evaluation, skipping cache usage')
                else:
                    cached_result = cache_mgr.refresh()
                    if cached_result:
                        metrics.counter_inc(name='anchore_policy_evaluation_cache_hits')
                        metrics.histogram_observe('anchore_policy_evaluation_cache_access_latency', time.time() - timer2,
                                                  status="hit")
                        log.info('Returning cached result of policy evaluation for {}/{}, with tag {} and bundle {} with digest {}. Last evaluation: {}'.format(user_id, image_id, tag, cache_mgr.bundle_id, cache_mgr.bundle_digest, cached_result.get('last_modified')))
                        return cached_result
                    else:
                        metrics.counter_inc(name='anchore_policy_evaluation_cache_misses')
                        metrics.histogram_observe('anchore_policy_evaluation_cache_access_latency', time.time() - timer2,
                                                  status="miss")
                        log.info('Policy evaluation not cached, or invalid, executing evaluation for {}/{} with tag {} and bundle {} with digest {}'.format(user_id, image_id, tag, cache_mgr.bundle_id, cache_mgr.bundle_digest))

            except Exception as ex:
                log.exception('Unexpected error operating on policy evaluation cache. Skipping use of cache.')

        else:
            log.info('Policy evaluation cache disabled. Executing evaluation')

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
                log.exception('Error executing policy bundle {} against image {} w/tag {}: {}'.format(bundle['id'], image_id, tag, e))
                return make_response_error('Internal bundle evaluation error', details={'message':'Cannot execute given policy against the image due to errors executing the policy bundle: {}'.format(e)}, in_httpcode=500), 500
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
            metrics.histogram_observe('anchore_policy_evaluation_time_seconds', time.time() - timer, status="fail")
        else:
            metrics.histogram_observe('anchore_policy_evaluation_time_seconds', time.time() - timer, status="success")

        result = resp.to_dict()

        # Never let the cache block returning results
        try:
            if evaluation_cache_enabled and cache_mgr is not None:
                cache_mgr.save(result)
        except Exception as ex:
            log.exception("Failed saving policy result in cache. Skipping and continuing.")

        db.commit()

        return result

    except HTTPException as e:
        db.rollback()
        log.exception('Caught exception in execution: {}'.format(e))
        raise
    except Exception as e:
        db.rollback()
        log.exception('Failed processing bundle evaluation: {}'.format(e))
        return make_response_error('Unexpected internal error', details={'message': str(e)}, in_httpcode=500), 500
    finally:
        db.close()


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
            return make_response_error('Image not found', in_httpcode=404), 404
        else:
            if force_refresh:
                log.info('Forcing refresh of vulnerabilities for {}/{}'.format(user_id, image_id))
                try:
                    vulns = rescan_image(img, db_session=db)
                    db.commit()
                except Exception as e:
                    log.exception('Error refreshing cve matches for image {}/{}'.format(user_id, image_id))
                    db.rollback()
                    return make_response_error('Error refreshing vulnerability listing for image.', in_httpcode=500)

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

        # select the nvd class once and be done
        _nvd_cls, _cpe_cls = select_nvd_classes(db)

        rows = []
        t = time.time()
        vulns = merge_nvd_metadata_image_packages(db, vulns, _nvd_cls, _cpe_cls)
        log.spew("Vuln timing merge {}".format(time.time() - t))

        t = time.time()
        for vuln, nvd_records in vulns:
            # Skip the vulnerability if the vendor_only flag is set to True and the issue won't be addressed by the vendor
            if vendor_only and vuln.fix_has_no_advisory():
                continue

            # rennovation this for new CVSS references
            cves = ''
            nvd_list = []
            all_data = {'nvd_data': nvd_list, 'vendor_data': [], 'advisory_data': {'cves': []}}

            if vuln.vulnerability.additional_metadata:
                all_data['advisory_data']['cves'] = vuln.vulnerability.additional_metadata.get('CVE', [])

            for nvd_record in nvd_records:
                nvd_list.extend(nvd_record.get_cvss_data_nvd())

            cves = json.dumps(all_data)

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

        log.spew("Vuln timing 1 {}".format(time.time() - t))

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
            t = time.time()
            all_cpe_matches = img.cpe_vulnerabilities(_nvd_cls=_nvd_cls, _cpe_cls=_cpe_cls)
            log.spew("Vuln timing 2 {}".format(time.time() - t))

            if not all_cpe_matches:
                all_cpe_matches = []

            cpe_hashes = {}
            api_endpoint = get_api_endpoint()

            for image_cpe, vulnerability_cpe in all_cpe_matches:
                link = vulnerability_cpe.parent.link
                if not link:
                    link = '{}/query/vulnerabilities?id={}'.format(api_endpoint, vulnerability_cpe.vulnerability_id)

                cpe_vuln_el = {
                    'vulnerability_id': vulnerability_cpe.vulnerability_id,
                    'severity': vulnerability_cpe.parent.severity,
                    'link': link,
                    'pkg_type': image_cpe.pkg_type,
                    'pkg_path': image_cpe.pkg_path,
                    'name': image_cpe.name,
                    'version': image_cpe.version,
                    'cpe': image_cpe.get_cpestring(),
                    'cpe23': image_cpe.get_cpe23string(),
                    'feed_name': vulnerability_cpe.feed_name,
                    'feed_namespace': vulnerability_cpe.namespace_name,
                    'nvd_data': vulnerability_cpe.parent.get_cvss_data_nvd(),
                    'vendor_data': vulnerability_cpe.parent.get_cvss_data_vendor(),
                    'fixed_in': vulnerability_cpe.get_fixed_in()
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
        return make_response_error(e, in_httpcode=500), 500
    finally:
        db.close()


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def ingress_image(ingress_request):
    """
    :param ingress_request json object specifying the identity of the image to sync
    :return: status result for image load
    """

    req = ImageIngressRequest.from_dict(ingress_request)
    try:
        # Try this synchronously for now to see how slow it really is
        conn_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_conn_timeout', DEFAULT_CACHE_CONN_TIMEOUT)
        read_timeout = ApiRequestContextProxy.get_service().configuration.get('catalog_client_read_timeout', DEFAULT_CACHE_READ_TIMEOUT)
        t = ImageLoadTask(req.user_id, req.image_id, url=req.fetch_url, content_conn_timeout=conn_timeout, content_read_timeout=read_timeout)
        result = t.execute()
        resp = ImageIngressResponse()
        if not result:
            resp.status = 'loaded'
        else:
            # We're doing a sync call above, so just send loaded. It should be 'accepted' once async works.
            resp.status = 'loaded'
        return resp.to_dict(), 200
    except Exception as e:
        log.exception('Error loading image into policy engine')
        return make_response_error(e,in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
        return make_response_error(e, in_httpcode=500), 500


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
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
        return make_response_error(e, in_httpcode=500), 500

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
        ipm_query = dbsession.query(ImagePackage).filter(ImagePackage.name==pkg_name).filter(ImagePackage.image_user_id==userId)
        cpm_query = dbsession.query(ImageCpe).filter(func.lower(ImageCpe.name)==func.lower(pkg_name)).filter(ImageCpe.image_user_id==userId)

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


advisory_cache = {}


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
        image_cpe_vlndb_matches = []

        (_nvd_cls, _cpe_cls) = select_nvd_classes(dbsession)

        ipm_query = dbsession.query(ImagePackageVulnerability).filter(ImagePackageVulnerability.vulnerability_id==id).filter(ImagePackageVulnerability.pkg_user_id==userId)
        icm_query = dbsession.query(ImageCpe,_cpe_cls).filter(_cpe_cls.vulnerability_id==id).filter(func.lower(ImageCpe.name)==_cpe_cls.name).filter(ImageCpe.image_user_id==userId).filter(ImageCpe.version==_cpe_cls.version)
        icm_vulndb_query = dbsession.query(ImageCpe, VulnDBCpe).filter(
            VulnDBCpe.vulnerability_id == id,
            func.lower(ImageCpe.name) == VulnDBCpe.name,
            ImageCpe.image_user_id == userId,
            ImageCpe.version == VulnDBCpe.version,
            VulnDBCpe.is_affected.is_(True)
        )

        if severity_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.vulnerability.has(severity=severity_filter))
            icm_query = icm_query.filter(_cpe_cls.parent.has(severity=severity_filter))  # might be slower than join
            icm_vulndb_query = icm_vulndb_query.filter(_cpe_cls.parent.has(severity=severity_filter))  # might be slower than join
        if namespace_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.vulnerability_namespace_name==namespace_filter)
            icm_query = icm_query.filter(_cpe_cls.namespace_name==namespace_filter)
            icm_vulndb_query = icm_vulndb_query.filter(VulnDBCpe.namespace_name == namespace_filter)
        if affected_package_filter:
            ipm_query = ipm_query.filter(ImagePackageVulnerability.pkg_name==affected_package_filter)
            icm_query = icm_query.filter(func.lower(ImageCpe.name)==func.lower(affected_package_filter))
            icm_vulndb_query = icm_vulndb_query.filter(func.lower(ImageCpe.name) == func.lower(affected_package_filter))

        image_package_matches = ipm_query#.all()
        image_cpe_matches = icm_query#.all()
        image_cpe_vlndb_matches = icm_vulndb_query

        log.debug("QUERY TIME: {}".format(time.time() - start))

        start = time.time()
        if image_package_matches or image_cpe_matches or image_cpe_vlndb_matches:
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
                    'name': image.pkg_name,
                    'version': image.pkg_version,
                    'type': image.pkg_type,
                    'namespace': image.vulnerability_namespace_name,
                    'severity': image.vulnerability.severity,
                }

                ret_hash[imageId]['vulnerable_packages'].append(pkg_el)
            log.debug("IMAGEOSPKG TIME: {}".format(time.time() - start))

            for cpe_matches in [image_cpe_matches, image_cpe_vlndb_matches]:
                start = time.time()
                for image_cpe, vulnerability_cpe in cpe_matches:
                    imageId = image_cpe.image_id
                    if imageId not in ret_hash:
                        ret_hash[imageId] = {'image': imageId_to_record.get(imageId, {}), 'vulnerable_packages': []}
                        pkg_hash[imageId] = {}
                    pkg_el = {
                        'name': image_cpe.name,
                        'version': image_cpe.version,
                        'type': image_cpe.pkg_type,
                        'namespace': "{}".format(vulnerability_cpe.namespace_name),
                        'severity': "{}".format(vulnerability_cpe.parent.severity),
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


def query_vulnerabilities(dbsession, ids, package_name_filter, package_version_filter, namespace):
    """
    Return vulnerability records with the matched criteria from the feed data

    :param dbsession: active db session to use
    :param ids: single string or list of string ids
    :param package_name_filter: string name to filter vulns by in the affected package list
    :param package_version_filter: version for corresponding package to filter by
    :param namespace: string or list of strings to filter namespaces by
    :return: list of dicts
    """

    return_object = []
    httpcode = 500

    # Normalize to a list
    if type(namespace) == str:
        namespace = [namespace]

    if type(ids) == str:
        ids = [ids]

    try:
        return_el_template = {
            'id': None,
            'namespace': None,
            'severity': None,
            'link': None,
            'affected_packages': None,
            'description': None,
            'references': None,
            'nvd_data': None,
            'vendor_data': None
        }

        # order_by ascending timestamp will result in dedup hash having only the latest information stored for return, if there are duplicate records for NVD
        (_nvd_cls, _cpe_cls) = select_nvd_classes(dbsession)

        # Set the relationship loader for use with the queries
        loader = orm.selectinload

        # Always fetch any matching nvd records, even if namespace doesn't match, since they are used for the cvss data
        qry = dbsession.query(_nvd_cls).options(loader(_nvd_cls.vulnerable_cpes)).filter(_nvd_cls.name.in_(ids)).order_by(asc(_nvd_cls.created_at))

        t1 = time.time()
        nvd_vulnerabilities = qry.all()
        nvd_vulnerabilities.extend(
            dbsession.query(VulnDBMetadata).options(loader(VulnDBMetadata.cpes)).filter(VulnDBMetadata.name.in_(ids)).order_by(asc(VulnDBMetadata.created_at)).all()
        )

        log.spew('Vuln query 1 timing: {}'.format(time.time() - t1))

        api_endpoint = get_api_endpoint()

        if not namespace or ('nvdv2:cves' in namespace):
            dedupped_return_hash = {}
            t1 = time.time()

            for vulnerability in nvd_vulnerabilities:
                link = vulnerability.link
                if not link:
                    link = '{}/query/vulnerabilities?id={}'.format(api_endpoint, vulnerability.name)

                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el['id'] = vulnerability.name
                namespace_el['namespace'] = vulnerability.namespace_name
                namespace_el['severity'] = vulnerability.severity
                namespace_el['link'] = link
                namespace_el['affected_packages'] = []
                namespace_el['description'] = vulnerability.description
                namespace_el['references'] = vulnerability.references
                namespace_el['nvd_data'] = vulnerability.get_cvss_data_nvd()
                namespace_el['vendor_data'] = vulnerability.get_cvss_data_vendor()

                for v_pkg in vulnerability.vulnerable_cpes:
                    if (not package_name_filter or package_name_filter == v_pkg.name) and (not package_version_filter or package_version_filter == v_pkg.version):
                        pkg_el = {
                            'name': v_pkg.name,
                            'version': v_pkg.version,
                            'type': '*',
                        }
                        namespace_el['affected_packages'].append(pkg_el)

                if not package_name_filter or (package_name_filter and namespace_el['affected_packages']):
                    dedupped_return_hash[namespace_el['id']] = namespace_el

            log.spew('Vuln merge took {}'.format(time.time() - t1))

            return_object.extend(list(dedupped_return_hash.values()))

        if namespace == ['nvdv2:cves']:
            # Skip if requested was 'nvd'
            vulnerabilities = []
        else:
            t1 = time.time()

            qry = dbsession.query(Vulnerability).options(loader(Vulnerability.fixed_in)).filter(Vulnerability.id.in_(ids))

            if namespace:
                if type(namespace) == str:
                    namespace = [namespace]

                qry = qry.filter(Vulnerability.namespace_name.in_(namespace))

            vulnerabilities = qry.all()

            log.spew('Vuln query 2 timing: {}'.format(time.time() - t1))

        if vulnerabilities:
            log.spew('Merging nvd data into the vulns')
            t1 = time.time()
            merged_vulns = merge_nvd_metadata(dbsession, vulnerabilities, _nvd_cls, _cpe_cls, already_loaded_nvds=nvd_vulnerabilities)
            log.spew('Vuln nvd query 2 timing: {}'.format(time.time() - t1))

            for entry in merged_vulns:
                vulnerability = entry[0]
                nvds = entry[1]
                namespace_el = {}
                namespace_el.update(return_el_template)
                namespace_el['id'] = vulnerability.id
                namespace_el['namespace'] = vulnerability.namespace_name
                namespace_el['severity'] = vulnerability.severity
                namespace_el['link'] = vulnerability.link
                namespace_el['affected_packages'] = []

                namespace_el['nvd_data'] = []
                namespace_el['vendor_data'] = []

                for nvd_record in nvds:
                    namespace_el['nvd_data'].extend(nvd_record.get_cvss_data_nvd())

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


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_vulnerabilities_get(id=None, affected_package=None, affected_package_version=None, namespace=None):
    try:
        log.info('Querying vulnerabilities')
        session = get_session()
        request_inputs = anchore_engine.apis.do_request_prep(connexion.request, default_params={'id': id, 'affected_package': affected_package, 'affected_package_version': affected_package_version, 'namespace': namespace})

        # override to ensure we got the array version, not the string version
        request_inputs['params']['id'] = id
        request_inputs['params']['namespace'] = namespace
        return_object, httpcode = query_vulnerabilities(session, id, affected_package, affected_package_version, namespace)
    except Exception as err:
        httpcode = 500
        return_object = str(err)
    finally:
        session.close()

    return (return_object, httpcode)


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_images_by_package_get(user_id, name=None, version=None, package_type=None):
    log.info('Querying images by package {}'.format(name))
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


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_images_by_vulnerability_get(user_id, vulnerability_id=None, severity=None, namespace=None, affected_package=None, vendor_only=True):
    log.info('Querying images by vulnerability {}'.format(vulnerability_id))
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


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_artifacts(user_id, image_id, artifact_type):
    db = get_session()
    try:
        log.info('Getting retrieved files from image {}/{}'.format(user_id, image_id))
        img = db.query(Image).get((image_id, user_id))
        if img:
            handlers = artifact_handlers.get(artifact_type)
            if not handlers:
                # Bad request
                return make_response_error('Invalid artifact type {}'.format(artifact_type), in_httpcode=400), 400

            if not handlers.get('filter') or not handlers.get('mapper'):
                raise Exception('incomplete artifact handler definition for {}'.format(artifact_type))

            filter_fn = handlers['filter']
            artifact_items = filter_fn(img).all()
            map_fn = handlers['mapper']

            artifact_listing = [map_fn(x) for x in artifact_items]
            return artifact_listing, 200
        else:
            return None, 404
    except HTTPException:
        raise
    except Exception as e:
        log.exception('Error processing GET request for artifacts on image {}/{}'.format(user_id, image_id))
        return make_response_error('Error getting artifacts from image {}/{}: {}'.format(user_id, image_id, e), in_httpcode=500), 500
    finally:
        db.rollback()


def retrieved_file_to_path(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    return artifact_record.artifact_key


def retrieved_file_to_mgs(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    log.info("File value: {}".format(artifact_record.binary_value))

    return {
        "path": artifact_record.artifact_key,
        "b64_content": ensure_str(base64.encodebytes(artifact_record.binary_value))
    }


def retrieved_files_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'retrieve_files', AnalysisArtifact.analyzer_artifact == 'file_content.all', AnalysisArtifact.analyzer_type == 'base')


def secret_search_to_path(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    return artifact_record.artifact_key


def secret_search_to_msg(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    return {
        "path": artifact_record.artifact_key,
        "matches": handle_search_json_value(artifact_record.json_value)
    }


def handle_search_json_value(search_json: dict):
    """
    Input is:
    {
      b64_key: [<line no for match>,...,]
    }

    ==>

    [
    {
      "name": str,
      "regex": str
      "matched_lines": [<int>,..., <int>]
    }
    }

    :param search_json:
    :return: dict
    """

    matches = []

    for (k, matched_lines) in search_json.items():
        key = ensure_str(base64.b64decode(ensure_bytes(k)))
        comps = key.split('=', 1)

        if len(comps) == 2:
            regex_name = comps[0]
            regex_value = comps[1]
        else:
            regex_value = comps[0]
            regex_name = ''

        matches.append(
            {
                "name": regex_name,
                "regex": regex_value,
                "lines": matched_lines
            }
        )

    return matches


def secret_scans_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'secret_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base')


def file_content_to_path(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    return artifact_record.artifact_key


def file_content_to_msg(artifact_record):
    """

    :param artifact_record:
    :return:
    """

    return {
        "path": artifact_record.artifact_key,
        "matches": handle_search_json_value(artifact_record.json_value)
    }


def file_content_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(AnalysisArtifact.analyzer_id == 'content_search', AnalysisArtifact.analyzer_artifact == 'regexp_matches.all', AnalysisArtifact.analyzer_type == 'base')


# Filter functions by name as used in the api
artifact_handlers = {
    'retrieved_files': {
        'filter': retrieved_files_filter,
        'mapper': retrieved_file_to_mgs
    },
    'secret_search': {
        'filter': secret_scans_filter,
        'mapper': secret_search_to_msg
    },
    'file_content_search': {
        'filter': file_content_filter,
        'mapper': file_content_to_msg
    }
}
