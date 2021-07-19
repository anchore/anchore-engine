"""
Controller for all synchronous web operations. These are handled by the main web service endpoint.

Async operations are handled by teh async_operations controller.

"""
import base64
import datetime
import enum
import hashlib
import json
import os
import time

import connexion
from sqlalchemy import func, or_
from werkzeug.exceptions import HTTPException

import anchore_engine.subsys.servicestatus
from anchore_engine import apis, utils
from anchore_engine.apis.authorization import INTERNAL_SERVICE_ALLOWED, get_authorizer
from anchore_engine.apis.context import ApiRequestContextProxy
from anchore_engine.clients.services import catalog, internal_client_for
from anchore_engine.clients.services.common import get_service_endpoint
from anchore_engine.common.helpers import make_response_error

# API models
from anchore_engine.common.models.policy_engine import GateSpec
from anchore_engine.common.models.policy_engine import Image as ImageMsg
from anchore_engine.common.models.policy_engine import (
    ImageIngressRequest,
    ImageIngressResponse,
    PolicyEvaluation,
    PolicyEvaluationProblem,
    PolicyValidationResponse,
    TriggerParamSpec,
    TriggerSpec,
)
from anchore_engine.db import (
    AnalysisArtifact,
    CachedPolicyEvaluation,
    Image,
    ImageCpe,
    ImagePackage,
)
from anchore_engine.db import get_thread_scoped_session as get_session
from anchore_engine.services.policy_engine.engine.policy.bundles import (
    build_bundle,
    build_empty_error_execution,
)
from anchore_engine.services.policy_engine.engine.policy.exceptions import (
    InitializationError,
    ValidationError,
)
from anchore_engine.services.policy_engine.engine.policy.gate import (
    ExecutionContext,
    Gate,
)
from anchore_engine.services.policy_engine.engine.tasks import ImageLoadTask
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    get_imageId_to_record,
)
from anchore_engine.services.policy_engine.engine.vulns.providers import (
    get_vulnerabilities_provider,
)

# Leave this here to ensure gates registry is fully loaded
from anchore_engine.subsys import logger as log
from anchore_engine.subsys import metrics
from anchore_engine.subsys.metrics import flask_metrics
from anchore_engine.utils import ensure_bytes, ensure_str

authorizer = get_authorizer()


DEFAULT_CACHE_CONN_TIMEOUT = (
    -1
)  # Disabled by default, can be set in config file. Seconds for connection to cache for policy evals
DEFAULT_CACHE_READ_TIMEOUT = (
    -1
)  # Disabled by default, can be set in config file. Seconds for first byte timeout for policy eval cache

# Toggle of lock usage, primarily for testing and debugging usage
feed_sync_locking_enabled = True

evaluation_cache_enabled = (
    os.getenv("ANCHORE_POLICY_ENGINE_EVALUATION_CACHE_ENABLED", "true").lower()
    == "true"
)

vulnerabilities_cache_enabled = (
    os.getenv("ANCHORE_POLICY_ENGINE_VULNERABILITIES_CACHE_ENABLED", "true").lower()
    == "true"
)


def get_api_endpoint():
    try:
        return get_service_endpoint("apiext").strip("/")
    except:
        log.warn(
            "Could not find valid apiext endpoint for links so will use policy engine endpoint instead"
        )
        try:
            return get_service_endpoint("policy_engine").strip("/")
        except:
            log.warn(
                "No policy engine endpoint found either, using default but invalid url"
            )
            return "http://<valid endpoint not found>"

    return ""


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

    return return_object, httpcode


class ImageMessageMapper(object):
    """
    Map the msg to db and vice-versa
    """

    rfc3339_date_fmt = "%Y-%m-%dT%H:%M:%SZ"

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

    if status.get("enabled") is not None and type(status.get("enabled")) == bool:
        evaluation_cache_enabled = status.get("enabled")
        return {"enabled": evaluation_cache_enabled}, 200
    else:
        return make_response_error(errmsg="Invalid request", in_httpcode=400), 400


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
        imgs = [
            msg_mapper.db_to_msg(i).to_json()
            for i in db.query(Image).filter(Image.user_id == user_id).all()
        ]
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
        log.info(
            "Deleting image {}/{} and all associated resources".format(
                user_id, image_id
            )
        )
        img = db.query(Image).get((image_id, user_id))
        if img:
            get_vulnerabilities_provider().delete_image_vulnerabilities(
                image=img, db_session=db
            )
            try:
                conn_timeout = ApiRequestContextProxy.get_service().configuration.get(
                    "catalog_client_conn_timeout", DEFAULT_CACHE_CONN_TIMEOUT
                )
                read_timeout = ApiRequestContextProxy.get_service().configuration.get(
                    "catalog_client_read_timeout", DEFAULT_CACHE_READ_TIMEOUT
                )
                mgr = EvaluationCacheManager(
                    img, None, None, conn_timeout, read_timeout
                )
                mgr.flush()
            except Exception as ex:
                log.exception(
                    "Could not delete evaluations for image {}/{} in the cache. May be orphaned".format(
                        user_id, image_id
                    )
                )

            db.delete(img)
            db.commit()
        else:
            db.rollback()

        # Idempotently return 204. This isn't properly RESTY, but idempotency on delete makes clients much cleaner.
        return None, 204
    except HTTPException:
        raise
    except Exception as e:
        log.exception(
            "Error processing DELETE request for image {}/{}".format(user_id, image_id)
        )
        db.rollback()
        return (
            make_response_error(
                "Error deleting image {}/{}: {}".format(user_id, image_id, e),
                in_httpcode=500,
            ),
            500,
        )


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
    if hasattr(eval_exception, "details") and callable(eval_exception.details):
        prob.details = eval_exception.details()
    elif hasattr(eval_exception, "message"):
        prob.details = eval_exception.message
    else:
        prob.details = str(eval_exception)

    prob.problem_type = eval_exception.__class__.__name__
    if hasattr(eval_exception, "severity") and eval_exception.severity:
        prob.severity = eval_exception.severity
    elif severity:
        prob.severity = severity
    else:
        prob.severity = "error"
    return prob


# Global cache for policy evaluations
class EvaluationCacheManager(object):
    class CacheStatus(enum.Enum):
        valid = "valid"  # The cached entry is a valid result
        stale = "stale"  # The entry is stale because a feed sync has occurred since last evaluation
        invalid = (
            "invalid"  # The entry is invalid because the bundle digest has changed
        )
        missing = "missing"  # No entry

    __cache_bucket__ = "policy-engine-evaluation-cache"

    def __init__(
        self,
        image_object,
        tag,
        bundle,
        storage_conn_timeout=-1,
        storage_read_timeout=-1,
    ):
        self.image = image_object
        self.tag = tag
        if bundle:
            self.bundle = bundle
            self.bundle_id = None

            if bundle.get("id") is None:
                raise ValueError("Invalid bundle format")
            else:
                self.bundle_id = bundle["id"]

            self.bundle_digest = self._digest_for_bundle()
        else:
            self.bundle = None
            self.bundle_id = None
            self.bundle_digest = None

        self._catalog_client = internal_client_for(
            catalog.CatalogClient, userId=self.image.user_id
        )
        self._default_catalog_conn_timeout = storage_conn_timeout
        self._default_catalog_read_timeout = storage_read_timeout

    def _digest_for_bundle(self):
        return hashlib.sha256(
            utils.ensure_bytes(json.dumps(self.bundle, sort_keys=True))
        ).hexdigest()

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
            if (
                self._should_evaluate(result)
                != EvaluationCacheManager.CacheStatus.valid
            ):
                self._delete_entry(result)
            else:
                match = result

        session.flush()

        if match:
            if match.is_archive_ref():
                bucket, key = match.archive_tuple()
                try:
                    with self._catalog_client.timeout_context(
                        self._default_catalog_conn_timeout,
                        self._default_catalog_read_timeout,
                    ) as timeout_client:
                        data = timeout_client.get_document(bucket, key)
                except:
                    log.exception(
                        "Unexpected error getting document {}/{} from archive".format(
                            bucket, key
                        )
                    )
                    data = None
            else:
                data = match.result.get("result")
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
                    with self._catalog_client.timeout_context(
                        self._default_catalog_conn_timeout,
                        self._default_catalog_read_timeout,
                    ) as timeout_client:
                        resp = timeout_client.delete_document(bucket, key)
                    break
                except:
                    log.exception(
                        "Could not delete policy eval from cache, will retry. Bucket={}, Key={}".format(
                            bucket, key
                        )
                    )
                    retry -= 1
            else:
                log.error(
                    "Could not flush policy eval from cache after all retries, may be orphaned. Will remove from index."
                )

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
        return (
            session.query(CachedPolicyEvaluation)
            .filter_by(
                user_id=self.image.user_id,
                image_id=self.image.id,
                eval_tag=self.tag,
                bundle_id=self.bundle_id,
            )
            .all()
        )

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
        key = (
            "sha256:"
            + hashlib.sha256(utils.ensure_bytes(str(eval.key_tuple()))).hexdigest()
        )
        with self._catalog_client.timeout_context(
            self._default_catalog_conn_timeout, self._default_catalog_read_timeout
        ) as timeout_client:
            resp = timeout_client.put_document(self.__cache_bucket__, key, result)

        if not resp:
            raise Exception("Failed cache write to archive store")

        str_result = json.dumps(result, sort_keys=True)
        result_digest = (
            "sha256:" + hashlib.sha256(utils.ensure_bytes(str_result)).hexdigest()
        )

        eval.add_remote_result(self.__cache_bucket__, key, result_digest)
        eval.last_modified = datetime.datetime.utcnow()

        # Update index
        session = get_session()
        return session.merge(eval)

    def _inputs_changed(self, cache_timestamp):
        # A feed sync has occurred since the eval was done or the image has been updated/reloaded, so inputs can have changed. Must be stale
        db = get_session()

        image_updated = self.image.last_modified > cache_timestamp

        return (
            image_updated
            or get_vulnerabilities_provider().is_image_vulnerabilities_updated(
                image=self.image, db_session=db, since=cache_timestamp
            )
        )

    def _should_evaluate(self, cache_entry: CachedPolicyEvaluation):
        if cache_entry is None:
            metrics.counter_inc(name="anchore_policy_evaluation_cache_misses_notfound")
            return EvaluationCacheManager.CacheStatus.missing

        # The cached result is not for this exact bundle content, so result is invalid
        if cache_entry.bundle_id != self.bundle_id:
            log.warn("Unexpectedly got a cached evaluation for a different bundle id")
            metrics.counter_inc(name="anchore_policy_evaluation_cache_misses_notfound")
            return EvaluationCacheManager.CacheStatus.missing

        if cache_entry.bundle_digest == self.bundle_digest:
            # A feed sync has occurred since the eval was done or the image has been updated/reloaded, so inputs can have changed. Must be stale
            if self._inputs_changed(cache_entry.last_modified):
                metrics.counter_inc(name="anchore_policy_evaluation_cache_misses_stale")
                return EvaluationCacheManager.CacheStatus.stale
            else:
                return EvaluationCacheManager.CacheStatus.valid
        else:
            metrics.counter_inc(name="anchore_policy_evaluation_cache_misses_invalid")
            return EvaluationCacheManager.CacheStatus.invalid

    def flush(self):
        """
        Flush all cache entries for the given image
        :return:
        """
        session = get_session()
        for entry in session.query(CachedPolicyEvaluation).filter_by(
            user_id=self.image.user_id, image_id=self.image.id
        ):
            try:
                self._delete_entry(entry)

            except:
                log.exception("Could not delete eval cache entry: {}".format(entry))

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
            tag = "*/*:*"

        try:
            img_obj = db.query(Image).get((image_id, user_id))
        except:
            return make_response_error("Image not found", in_httpcode=404), 404

        if not img_obj:
            log.info(
                "Request for evaluation of image that cannot be found: user_id = {}, image_id = {}".format(
                    user_id, image_id
                )
            )
            return make_response_error("Image not found", in_httpcode=404), 404

        if evaluation_cache_enabled:
            timer2 = time.time()
            try:
                try:
                    conn_timeout = (
                        ApiRequestContextProxy.get_service().configuration.get(
                            "catalog_client_conn_timeout", DEFAULT_CACHE_CONN_TIMEOUT
                        )
                    )
                    read_timeout = (
                        ApiRequestContextProxy.get_service().configuration.get(
                            "catalog_client_read_timeout", DEFAULT_CACHE_READ_TIMEOUT
                        )
                    )
                    cache_mgr = EvaluationCacheManager(
                        img_obj, tag, bundle, conn_timeout, read_timeout
                    )
                except ValueError as err:
                    log.warn(
                        "Could not leverage cache due to error in bundle data: {}".format(
                            err
                        )
                    )
                    cache_mgr = None

                if cache_mgr is None:
                    log.info(
                        "Could not initialize cache manager for policy evaluation, skipping cache usage"
                    )
                else:
                    cached_result = cache_mgr.refresh()
                    if cached_result:
                        metrics.counter_inc(name="anchore_policy_evaluation_cache_hits")
                        metrics.histogram_observe(
                            "anchore_policy_evaluation_cache_access_latency",
                            time.time() - timer2,
                            status="hit",
                        )
                        log.info(
                            "Returning cached result of policy evaluation for {}/{}, with tag {} and bundle {} with digest {}. Last evaluation: {}".format(
                                user_id,
                                image_id,
                                tag,
                                cache_mgr.bundle_id,
                                cache_mgr.bundle_digest,
                                cached_result.get("last_modified"),
                            )
                        )
                        return cached_result
                    else:
                        metrics.counter_inc(
                            name="anchore_policy_evaluation_cache_misses"
                        )
                        metrics.histogram_observe(
                            "anchore_policy_evaluation_cache_access_latency",
                            time.time() - timer2,
                            status="miss",
                        )
                        log.info(
                            "Policy evaluation not cached, or invalid, executing evaluation for {}/{} with tag {} and bundle {} with digest {}".format(
                                user_id,
                                image_id,
                                tag,
                                cache_mgr.bundle_id,
                                cache_mgr.bundle_digest,
                            )
                        )

            except Exception as ex:
                log.exception(
                    "Unexpected error operating on policy evaluation cache. Skipping use of cache."
                )

        else:
            log.info("Policy evaluation cache disabled. Executing evaluation")

        # Build bundle exec.
        problems = []
        executable_bundle = None
        try:
            # Allow deprecated gates here to support upgrade cases from old policy bundles.
            executable_bundle = build_bundle(bundle, for_tag=tag, allow_deprecated=True)
            if executable_bundle.init_errors:
                problems = executable_bundle.init_errors
        except InitializationError as e:
            log.exception("Bundle construction and initialization returned errors")
            problems = e.causes

        eval_result = None
        if not problems:
            # Execute bundle
            try:
                eval_result = executable_bundle.execute(
                    img_obj, tag, ExecutionContext(db_session=db, configuration={})
                )
            except Exception as e:
                log.exception(
                    "Error executing policy bundle {} against image {} w/tag {}: {}".format(
                        bundle["id"], image_id, tag, e
                    )
                )
                return (
                    make_response_error(
                        "Internal bundle evaluation error",
                        details={
                            "message": "Cannot execute given policy against the image due to errors executing the policy bundle: {}".format(
                                e
                            )
                        },
                        in_httpcode=500,
                    ),
                    500,
                )
        else:
            # Construct a failure eval with details on the errors and mappings to send to client
            eval_result = build_empty_error_execution(
                img_obj, tag, executable_bundle, errors=problems, warnings=[]
            )
            if (
                executable_bundle
                and executable_bundle.mapping
                and len(executable_bundle.mapping.mapping_rules) == 1
            ):
                eval_result.executed_mapping = executable_bundle.mapping.mapping_rules[
                    0
                ]

        resp = PolicyEvaluation()
        resp.user_id = user_id
        resp.image_id = image_id
        resp.tag = tag
        resp.bundle = bundle
        resp.matched_mapping_rule = (
            eval_result.executed_mapping.json()
            if eval_result.executed_mapping
            else False
        )
        resp.last_modified = int(time.time())
        resp.final_action = eval_result.bundle_decision.final_decision.name
        resp.final_action_reason = eval_result.bundle_decision.reason
        resp.matched_whitelisted_images_rule = (
            eval_result.bundle_decision.whitelisted_image.json()
            if eval_result.bundle_decision.whitelisted_image
            else False
        )
        resp.matched_blacklisted_images_rule = (
            eval_result.bundle_decision.blacklisted_image.json()
            if eval_result.bundle_decision.blacklisted_image
            else False
        )
        resp.result = eval_result.as_table_json()
        resp.created_at = int(time.time())
        resp.evaluation_problems = [
            problem_from_exception(i) for i in eval_result.errors
        ]
        resp.evaluation_problems += [
            problem_from_exception(i) for i in eval_result.warnings
        ]
        if resp.evaluation_problems:
            for i in resp.evaluation_problems:
                log.warn(
                    "Returning evaluation response for image {}/{} w/tag {} and bundle {} that contains error: {}".format(
                        user_id, image_id, tag, bundle["id"], json.dumps(i.to_json())
                    )
                )
            metrics.histogram_observe(
                "anchore_policy_evaluation_time_seconds",
                time.time() - timer,
                status="fail",
            )
        else:
            metrics.histogram_observe(
                "anchore_policy_evaluation_time_seconds",
                time.time() - timer,
                status="success",
            )

        result = resp.to_json()

        # Never let the cache block returning results
        try:
            if evaluation_cache_enabled and cache_mgr is not None:
                cache_mgr.save(result)
        except Exception as ex:
            log.exception(
                "Failed saving policy result in cache. Skipping and continuing."
            )

        db.commit()

        return result

    except HTTPException as e:
        db.rollback()
        log.exception("Caught exception in execution: {}".format(e))
        raise
    except Exception as e:
        db.rollback()
        log.exception("Failed processing bundle evaluation: {}".format(e))
        return (
            make_response_error(
                "Unexpected internal error",
                details={"message": str(e)},
                in_httpcode=500,
            ),
            500,
        )
    finally:
        db.close()


@flask_metrics.do_not_track()
@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def get_image_vulnerabilities(user_id, image_id, force_refresh=False, vendor_only=True):
    """
    Return the vulnerability listing for the specified image and load from catalog if not found and specifically asked
    to do so.

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
        if not img:
            return make_response_error("Image not found", in_httpcode=404), 404

        provider = get_vulnerabilities_provider()
        report = provider.get_image_vulnerabilities_json(
            image=img,
            vendor_only=vendor_only,
            db_session=db,
            force_refresh=force_refresh,
            use_store=True,
        )

        db.commit()
        return report, 200

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        log.exception(
            "Error checking image {}, {} for vulnerabiltiies. Rolling back".format(
                user_id, image_id
            )
        )
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

    req = ImageIngressRequest.from_json(ingress_request)
    if not req.user_id:
        raise ValueError("user_id")
    if not req.image_id:
        raise ValueError("image_id")

    try:
        # Try this synchronously for now to see how slow it really is
        conn_timeout = ApiRequestContextProxy.get_service().configuration.get(
            "catalog_client_conn_timeout", DEFAULT_CACHE_CONN_TIMEOUT
        )
        read_timeout = ApiRequestContextProxy.get_service().configuration.get(
            "catalog_client_read_timeout", DEFAULT_CACHE_READ_TIMEOUT
        )
        t = ImageLoadTask(
            req.user_id,
            req.image_id,
            url=req.fetch_url,
            content_conn_timeout=conn_timeout,
            content_read_timeout=read_timeout,
        )
        result = t.execute()
        resp = ImageIngressResponse()
        if not result:
            resp.status = "loaded"
        else:
            # We're doing a sync call above, so just send loaded. It should be 'accepted' once async works.
            resp.status = "loaded"
        resp.problems = list()
        return resp.to_json(), 200
    except Exception as e:
        log.exception("Error loading image into policy engine")
        return make_response_error(e, in_httpcode=500), 500


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
        except ValidationError as e:
            problems.append(e)
        except InitializationError as e:
            # Expand any validation issues
            problems = e.causes

        resp.valid = len(problems) == 0
        resp.validation_details = [
            problem_from_exception(i, severity="error") for i in problems
        ]
        return resp.to_json()

    except HTTPException as e:
        log.exception("Caught exception in execution: {}".format(e))
        raise
    except Exception as e:
        log.exception("Failed processing bundle evaluation: {}".format(e))
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
            g.description = v.__description__ if v.__description__ else ""
            g.triggers = []
            if hasattr(v, "__superceded_by__"):
                g.superceded_by = v.__superceded_by__
            else:
                g.superceded_by = None

            if hasattr(v, "__lifecycle_state__"):
                g.state = v.__lifecycle_state__.name
            else:
                g.state = "active"

            for t in v.__triggers__:
                tr = TriggerSpec()
                tr.name = t.__trigger_name__
                tr.description = t.__description__ if t.__description__ else ""
                tr.parameters = []
                if hasattr(t, "__superceded_by__"):
                    tr.superceded_by = t.__superceded_by__
                else:
                    tr.superceded_by = None
                if hasattr(t, "__lifecycle_state__"):
                    tr.state = t.__lifecycle_state__.name
                else:
                    tr.state = "active"

                params = t._parameters()
                if params:
                    param_list = sorted(
                        list(params.values()), key=lambda x: x.sort_order
                    )
                    for param in param_list:
                        tps = TriggerParamSpec()
                        tps.name = param.name
                        tps.description = param.description
                        tps.example = param.example
                        tps.validator = param.validator.json()
                        tps.required = param.required
                        if hasattr(param, "__superceded_by__"):
                            tps.superceded_by = param.__superceded_by__
                        else:
                            tps.superceded_by = None

                        if hasattr(param, "__lifecycle_state__"):
                            tps.state = param.__lifecycle_state__.name
                        else:
                            tps.state = "active"

                        tr.parameters.append(tps)

                g.triggers.append(tr)

            doc.append(g.to_json())

            doc = sorted(doc, key=lambda x: x["state"])

        return doc, 200

    except Exception as e:
        log.exception("Error describing gate system")
        return make_response_error(e, in_httpcode=500), 500


def query_images_by_package(dbsession, request_inputs):
    user_auth = request_inputs["auth"]
    method = request_inputs["method"]
    params = request_inputs["params"]
    userId = request_inputs["userId"]

    return_object = {}
    httpcode = 500

    pkg_name = request_inputs.get("params", {}).get("name", None)
    pkg_version = request_inputs.get("params", {}).get("version", None)
    pkg_type = request_inputs.get("params", {}).get("package_type", None)

    ret_hash = {}
    pkg_hash = {}
    try:
        ipm_query = (
            dbsession.query(ImagePackage)
            .filter(ImagePackage.name == pkg_name)
            .filter(ImagePackage.image_user_id == userId)
        )
        cpm_query = (
            dbsession.query(ImageCpe)
            .filter(func.lower(ImageCpe.name) == func.lower(pkg_name))
            .filter(ImageCpe.image_user_id == userId)
        )

        if pkg_version and pkg_version != "None":
            ipm_query = ipm_query.filter(
                or_(
                    ImagePackage.version == pkg_version,
                    ImagePackage.fullversion == pkg_version,
                )
            )
            cpm_query = cpm_query.filter(ImageCpe.version == pkg_version)
        if pkg_type and pkg_type != "None":
            ipm_query = ipm_query.filter(ImagePackage.pkg_type == pkg_type)
            cpm_query = cpm_query.filter(ImageCpe.pkg_type == pkg_type)

        image_package_matches = ipm_query
        cpe_package_matches = cpm_query

        # ipm_dbfilter = {'name': pkg_name}
        # cpm_dbfilter = {'name': pkg_name}

        # if pkg_version and pkg_version != 'None':
        #    ipm_dbfilter['version'] = pkg_version
        #    cpm_dbfilter['version'] = pkg_version
        # if pkg_type and pkg_type != 'None':
        #    ipm_dbfilter['pkg_type'] = pkg_type
        #    cpm_dbfilter['pkg_type'] = pkg_type

        # image_package_matches = dbsession.query(ImagePackage).filter_by(**ipm_dbfilter).all()
        # cpe_package_matches = dbsession.query(ImageCpe).filter_by(**cpm_dbfilter).all()

        if image_package_matches or cpe_package_matches:
            imageId_to_record = get_imageId_to_record(userId, dbsession=dbsession)

            for image in image_package_matches:
                imageId = image.image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {
                        "image": imageId_to_record.get(imageId, {}),
                        "packages": [],
                    }
                    pkg_hash[imageId] = {}

                pkg_el = {
                    "name": image.name,
                    "version": image.fullversion,
                    "type": image.pkg_type,
                }
                phash = hashlib.sha256(json.dumps(pkg_el).encode("utf-8")).hexdigest()
                if not pkg_hash[imageId].get(phash, False):
                    ret_hash[imageId]["packages"].append(pkg_el)
                pkg_hash[imageId][phash] = True

            for image in cpe_package_matches:
                imageId = image.image_id
                if imageId not in ret_hash:
                    ret_hash[imageId] = {
                        "image": imageId_to_record.get(imageId, {}),
                        "packages": [],
                    }
                    pkg_hash[imageId] = {}

                pkg_el = {
                    "name": image.name,
                    "version": image.version,
                    "type": image.pkg_type,
                }
                phash = hashlib.sha256(json.dumps(pkg_el).encode("utf-8")).hexdigest()
                if not pkg_hash[imageId].get(phash, False):
                    ret_hash[imageId]["packages"].append(pkg_el)
                pkg_hash[imageId][phash] = True

        matched_images = list(ret_hash.values())
        return_object = {"matched_images": matched_images}
        httpcode = 200
    except Exception as err:
        log.error("{}".format(err))
        return_object = make_response_error(err, in_httpcode=httpcode)

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_vulnerabilities_get(
    id=None, affected_package=None, affected_package_version=None, namespace=None
):
    log.info("Querying vulnerabilities")

    session = get_session()

    try:
        # Normalize to a list
        if type(namespace) == str:
            namespace = [namespace]

        if type(id) == str:
            ids = [id]
        else:
            ids = id

        return_object = get_vulnerabilities_provider().get_vulnerabilities(
            ids, affected_package, affected_package_version, namespace, session
        )

        httpcode = 200
    except Exception as err:
        log.exception("Error querying vulnerabilities")
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
    finally:
        session.close()

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_images_by_package_get(user_id, name=None, version=None, package_type=None):
    log.info("Querying images by package {}".format(name))
    try:
        session = get_session()
        request_inputs = anchore_engine.apis.do_request_prep(
            connexion.request,
            default_params={
                "name": name,
                "version": version,
                "package_type": package_type,
            },
        )
        return_object, httpcode = query_images_by_package(session, request_inputs)
    except Exception as err:
        httpcode = 500
        return_object = str(err)
    finally:
        session.close()

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def query_images_by_vulnerability_get(
    user_id,
    vulnerability_id=None,
    severity=None,
    namespace=None,
    affected_package=None,
    vendor_only=True,
):
    log.info("Querying images by vulnerability {}".format(vulnerability_id))

    session = get_session()

    try:
        # request prep is unnecessary but keeping it around for now to avoid weird corner cases
        request_inputs = apis.do_request_prep(
            connexion.request,
            default_params={
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "namespace": namespace,
                "affected_package": affected_package,
                "vendor_only": vendor_only,
            },
        )

        request_account_id = request_inputs["userId"]
        request_id = request_inputs.get("params", {}).get("vulnerability_id", None)
        request_severity_filter = request_inputs.get("params", {}).get("severity", None)
        request_namespace_filter = request_inputs.get("params", {}).get(
            "namespace", None
        )
        request_affected_package_filter = request_inputs.get("params", {}).get(
            "affected_package", None
        )
        request_vendor_only = request_inputs.get("params", {}).get("vendor_only", True)

        return_object = get_vulnerabilities_provider().get_images_by_vulnerability(
            request_account_id,
            request_id,
            request_severity_filter,
            request_namespace_filter,
            request_affected_package_filter,
            request_vendor_only,
            session,
        )

        httpcode = 200

    except Exception as err:
        log.exception("Error querying images by vulnerability")
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
    finally:
        session.close()

    return return_object, httpcode


@authorizer.requires_account(with_types=INTERNAL_SERVICE_ALLOWED)
def list_artifacts(user_id, image_id, artifact_type):
    db = get_session()
    try:
        log.info("Getting retrieved files from image {}/{}".format(user_id, image_id))
        img = db.query(Image).get((image_id, user_id))
        if img:
            handlers = artifact_handlers.get(artifact_type)
            if not handlers:
                # Bad request
                return (
                    make_response_error(
                        "Invalid artifact type {}".format(artifact_type),
                        in_httpcode=400,
                    ),
                    400,
                )

            if not handlers.get("filter") or not handlers.get("mapper"):
                raise Exception(
                    "incomplete artifact handler definition for {}".format(
                        artifact_type
                    )
                )

            filter_fn = handlers["filter"]
            artifact_items = filter_fn(img).all()
            map_fn = handlers["mapper"]

            artifact_listing = [map_fn(x) for x in artifact_items]
            return artifact_listing, 200
        else:
            return None, 404
    except HTTPException:
        raise
    except Exception as e:
        log.exception(
            "Error processing GET request for artifacts on image {}/{}".format(
                user_id, image_id
            )
        )
        return (
            make_response_error(
                "Error getting artifacts from image {}/{}: {}".format(
                    user_id, image_id, e
                ),
                in_httpcode=500,
            ),
            500,
        )
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
        "b64_content": ensure_str(base64.encodebytes(artifact_record.binary_value)),
    }


def retrieved_files_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(
        AnalysisArtifact.analyzer_id == "retrieve_files",
        AnalysisArtifact.analyzer_artifact == "file_content.all",
        AnalysisArtifact.analyzer_type == "base",
    )


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
        "matches": handle_search_json_value(artifact_record.json_value),
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
        comps = key.split("=", 1)

        if len(comps) == 2:
            regex_name = comps[0]
            regex_value = comps[1]
        else:
            regex_value = comps[0]
            regex_name = ""

        matches.append(
            {"name": regex_name, "regex": regex_value, "lines": matched_lines}
        )

    return matches


def secret_scans_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(
        AnalysisArtifact.analyzer_id == "secret_search",
        AnalysisArtifact.analyzer_artifact == "regexp_matches.all",
        AnalysisArtifact.analyzer_type == "base",
    )


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
        "matches": handle_search_json_value(artifact_record.json_value),
    }


def file_content_filter(img_record):
    """
    Return the artifacts filter for retrieved files
    :param img_record:
    :return:
    """
    return img_record.analysis_artifacts.filter(
        AnalysisArtifact.analyzer_id == "content_search",
        AnalysisArtifact.analyzer_artifact == "regexp_matches.all",
        AnalysisArtifact.analyzer_type == "base",
    )


# Filter functions by name as used in the api
artifact_handlers = {
    "retrieved_files": {
        "filter": retrieved_files_filter,
        "mapper": retrieved_file_to_mgs,
    },
    "secret_search": {"filter": secret_scans_filter, "mapper": secret_search_to_msg},
    "file_content_search": {
        "filter": file_content_filter,
        "mapper": file_content_to_msg,
    },
}
