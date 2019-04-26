"""
Module for handling archive tasks
"""
import copy
import json
import datetime
import tarfile
import tempfile
import os
import io
import time
import uuid

from sqlalchemy import or_, and_
from anchore_engine.apis.serialization import JitSchema, JsonMappedMixin
from anchore_engine.utils import datetime_to_rfc3339, ensure_str, ensure_bytes
from anchore_engine.clients.services.policy_engine import PolicyEngineClient
from anchore_engine.clients.services import internal_client_for
from anchore_engine.subsys import logger, archive, object_store
from anchore_engine.subsys.object_store.manager import ObjectStorageManager
from anchore_engine.db import db_catalog_image, db_catalog_image_docker, db_policyeval, session_scope, db_archived_images, ArchivedImage, \
    CatalogImageDocker, CatalogImage, Session, ArchiveTransitionRule, ArchiveTransitions

from anchore_engine.db.entities import exceptions as db_exceptions
from anchore_engine.configuration import localconfig
from anchore_engine.services.catalog.catalog_impl import image_imageDigest
from anchore_engine.subsys.events import ImageArchiveDeleted, ImageRestored, ImageArchived, ImageArchiveDeleteFailed, ImageArchivingFailed, ImageRestoreFailed


# Json serialization stuff...
from marshmallow import fields, post_load

DRY_RUN_ENV_VAR = 'ANCHORE_ANALYSIS_ARCHIVE_DRYRUN_ENABLED'
DRY_RUN_MODE = (os.getenv(DRY_RUN_ENV_VAR, 'false').lower() == 'true')

_add_event_fn = None
from threading import RLock
event_init_lock = RLock()


def init_events(handler_fn=None):
    """
    Indirection to allow injection of different handler for testing and delay the binding to catalog specific code unless invoked

    :param handler_fn: a callable that takes two args: event (type Event) and quiet (bool)
    :return:
    """

    global _add_event_fn, event_init_lock
    with event_init_lock:
        if not handler_fn and _add_event_fn is None:
            from anchore_engine.services.catalog import _add_event
            _add_event_fn = _add_event


def add_event(event):
    """
    Adds an event to the system. Will swallow all exceptions to ensure clean exit even in finally blocks
    :param event:
    :return:
    """

    global _add_event_fn
    # Unsafe check but the init call is safe so at most this is redundant but safe and only impacts init
    try:
        if _add_event_fn is None:
            init_events()
        return _add_event_fn(event)
    except Exception as ex:
        logger.exception('Uncaught exception from event emitter: {}'.format(event))


class ArtifactNotFound(Exception):
    pass


class ManifestNotFound(ArtifactNotFound):
    pass


class MetadataNotFound(Exception):
    pass


class ObjectStoreLocation(JsonMappedMixin):
    class ObjectStoreLocationV1Schema(JitSchema):
        bucket = fields.Str()
        key = fields.Str()

        @post_load
        def make(self, data):
            return ObjectStoreLocation(**data)

    __schema__ = ObjectStoreLocationV1Schema()

    def __init__(self, bucket=None, key=None):
        self.bucket = bucket
        self.key = key


class TarballLocation(JsonMappedMixin):
    class TarballLocationV1Schema(JitSchema):
        tarfile_path = fields.Str()

        @post_load
        def make(self, data):
            return TarballLocation(**data)

    __schema__ = TarballLocationV1Schema()

    def __init__(self, tarfile_path=None):
        self.tarfile_path = tarfile_path


class Artifact(JsonMappedMixin):
    class ArtifactV1Schema(JitSchema):

        name = fields.Str()
        metadata = fields.Dict(allow_none=True)
        source = fields.Nested(ObjectStoreLocation.ObjectStoreLocationV1Schema, allow_none=True)
        dest = fields.Nested(TarballLocation.TarballLocationV1Schema, allow_none=True)

        @post_load
        def make(self, data):
            return Artifact(**data)

    __schema__ = ArtifactV1Schema()

    def __init__(self, name=None, metadata=None, source=None, dest=None):
        self.name = name
        self.metadata = metadata
        self.source = source
        self.dest = dest


class ArchiveManifest(JsonMappedMixin):
    class ArchiveManifestV1Schema(JitSchema):
        image_digest = fields.Str()
        account = fields.Str()
        archived_at = fields.DateTime()
        metadata = fields.Dict()
        artifacts = fields.List(fields.Nested(Artifact.ArtifactV1Schema))

        @post_load
        def make_manifest(self, data):
            return ArchiveManifest(**data)

    __schema__ = ArchiveManifestV1Schema()

    def __init__(self, account=None, image_digest=None, metadata=None, artifacts=None, archived_at=datetime.datetime.utcnow()):
        self.account = account
        self.image_digest = image_digest
        self.archived_at = archived_at
        self.metadata = metadata
        self.artifacts = artifacts


class ImageArchive(object):
    """
    An archived image with backing storage (e.g. tarball).
    Can be read and written, but only one at a time.

    """

    __manifest_name__ = 'archive_manifest'

    def __init__(self, backing_path=None, account=None, image_digest=None, mode='r'):
        if mode not in ['r', 'w']:
            raise ValueError('mode must be either "r" or "w"')

        self.manifest = ArchiveManifest()
        self.manifest.metadata = {}
        self.manifest.artifacts = []
        self.manifest.image_digest = image_digest
        self.manifest.account = account

        self.backing_file_path = backing_path
        self._tarfile = None
        self._tar_mode = mode

    @property
    def account(self):
        return self.manifest.account

    @account.setter
    def account(self, account):
        self.manifest.account = account

    @property
    def image_digest(self):
        return self.manifest.image_digest

    @image_digest.setter
    def image_digest(self, image_digest):
        self.manifest.image_digest = image_digest

    @property
    def metadata(self):
        return self.manifest.metadata

    def add_artifact(self, name, source=None, data=None, metadata=None):
        art = Artifact(name=name, source=source, dest=TarballLocation(name), metadata=metadata)

        self.manifest.artifacts.append(art)

        if type(data) == str:
            input = io.StringIO(data)
        else:
            input = io.BytesIO(data)

        tinfo = tarfile.TarInfo(name)
        tinfo.size = len(data)

        self._tarfile.addfile(tarinfo=tinfo, fileobj=input)
        return art

    def extract_artifact(self, name):
        """
        :param name: artifact to extract
        :return:
        """
        f = self._tarfile.extractfile(name)
        return f.read()

    def remove_artifact(self):
        pass

    def _is_open(self):
        return self._tarfile and not self._tarfile.closed

    @classmethod
    def for_reading(cls, path):
        return ImageArchive(backing_path=path, mode='r')

    @classmethod
    def for_writing(cls, path):
        return ImageArchive(backing_path=path, mode='w')

    def __enter__(self):
        if not self._tarfile or self._tarfile.closed:
            self._tarfile = tarfile.open(name=self.backing_file_path, mode='{}:gz'.format(self._tar_mode))

        if self._tar_mode == 'r':
            # Try to load the manifest
            manifest_data = self._tarfile.extractfile(self.__manifest_name__)
            self.manifest = ArchiveManifest.from_json(json.loads(ensure_str(manifest_data.read())))

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Dump all metadata to the backing storage and sync state.

        This can be called multiple times safely, but is not thread-safe.

        Mostly, this syncs the manifest data into the tarball.

        :return:
        """
        if exc_type is None:
            # Clean exit

            if self._tar_mode in ['x', 'w']:
                # Write the manifest into the tar file
                d = ensure_bytes(self.manifest.to_json_str())
                sio = io.BytesIO(d)
                info = tarfile.TarInfo('archive_manifest')
                info.size = len(d)
                self._tarfile.addfile(tarinfo=info, fileobj=sio)

        if self._tarfile and not self._tarfile.closed:
            self._tarfile.close()


class RuleMatch(object):
    """
    Match obj for tracking matches outside of transaction scope and/or in a smaller memory footprint
    """
    def __init__(self, rule, digest, tag_tuple):
        """
        :param rule: rule id (str)
        :param digest: image digest (str)
        :param tag_tuple: tupe of (registry, repo, tag) for the digest
        """

        self.rule = rule
        self.digest = digest
        self.tag_tuple = tag_tuple


class ImageAnalysisArchiver(object):
    """
    Reads rules for the account and archives things that match. Only processes 'archive' rules.
    This is a unit-of-work oriented archiver intended for async usage, not serving api calls.
    """

    def __init__(self, account, parent_task_id=None, delete_source=False):
        self.account = account
        self.task_id = uuid.uuid4().hex
        self.parent_task_id = parent_task_id
        self.delete_source = delete_source


    def _get_globals(self, session):
        # Select rules that are archive transitions, and either global, or specific to this account
        rules = session.query(ArchiveTransitionRule).filter_by(transition=ArchiveTransitions.archive, system_global=True).all()
        return rules

    def _get_account_rules(self, session):
        # Select rules that are archive transitions, and either global, or specific to this account
        rules = session.query(ArchiveTransitionRule).filter_by(transition=ArchiveTransitions.archive, account=self.account).all()
        return rules

    # NOTE: still should process rules in per-account order to ensure no strange rule eval of duplicate tags/digests across accounts
    def _process_rules(self, rules, session):
        def lookup_tags(account, digest):
            return session.query(CatalogImageDocker).filter_by(userId=account, imageDigest=digest).all()

        archive_merger = ArchiveTransitionTask.TagRuleMatchMerger(self.task_id, self.account, lookup_tags)

        for rule in rules:
            logger.debug('Running archive transition rule: {}'.format(rule))

            matches = self._find_candidates(session, rule)
            logger.debug('Rule: {} matches {}'.format(rule, matches))
            archive_merger.add_rule_result(rule, matches)

        return archive_merger.full_matched_digests()

    def _do_archive(self, to_archive):
        for img_digest in to_archive:
            logger.info('Archiving image {}/{}'.format(self.account, img_digest))
            try:
                if not DRY_RUN_MODE:
                    t = ArchiveImageTask(account=self.account, image_digest=img_digest)
                    status, msg = t.run()
                    logger.info('Archive task result: status={}, detail={}'.format(status, msg))

                    if status == 'archived':
                        logger.info('Deleting source analysis for image {} after archiving'.format(img_digest))
                        if self.delete_source:
                            inputs = {
                                'method': 'DELETE',
                                'params': {'force': True},
                                'auth': ('', ''),
                                'userId': self.account
                            }
                            with session_scope() as session:
                                resp, http_code = image_imageDigest(session, request_inputs=inputs, imageDigest=img_digest, bodycontent=None)
                                if http_code not in [200, 204]:
                                    logger.error('Could not delete image analysis: {}'.format(resp))
                                else:
                                    logger.info("Deleted image analysis for {} successfully".format(img_digest))
                else:
                    logger.info('Archive task DRY_RUN mode enabled via {}, would have archived image {}/{}'.format(DRY_RUN_ENV_VAR, self.account, img_digest))
            except Exception as ex:
                logger.exception('Caught unhandled exception in archive task')

    def new_run(self):
        try:
            logger.debug('Processing globally-scoped rules')
            with session_scope() as session:
                rules = self._get_globals(session)
                to_archive = self._process_rules(rules, session)
            self._do_archive(to_archive)
        except Exception as e:
            logger.exception('Unexpected exception caught in global archive transition rule handling for account {}'.format(self.account))

        try:
            logger.debug('Processing account-scoped rules')
            with session_scope() as session:
                rules = self._get_account_rules(session)
                to_archive = self._process_rules(rules, session)
            self._do_archive(to_archive)
        except Exception as e:
            logger.exception('Unexpected exception caught in account-local archive transition rule handling for account {}'.format(self.account))

    def run(self):
        return self.new_run()

    def _old_run(self):
        """
        Older centralized function pre-global rule support.
        :return:
        """
        with session_scope() as session:
            rules = session.query(ArchiveTransitionRule).filter_by(account=self.account, transition=ArchiveTransitions.archive).all()
            logger.debug('Running archive transition rules: {}'.format(rules))

            def lookup_tags(account, digest):
                return session.query(CatalogImageDocker).filter_by(userId=account, imageDigest=digest).all()

            archive_merger = ArchiveTransitionTask.TagRuleMatchMerger(self.task_id, self.account, lookup_tags)

            for rule in rules:
                logger.debug('Running archive transition rule: {}'.format(rule))

                matches = self._find_candidates(session, rule)
                logger.debug('Rule: {} matches {}'.format(rule, matches))
                archive_merger.add_rule_result(rule, matches)

            to_archive = archive_merger.full_matched_digests()

        for img_digest in to_archive:
            logger.info('Archiving image {}/{}'.format(self.account, img_digest))
            try:
                if not DRY_RUN_MODE:
                    t = ArchiveImageTask(account=self.account, image_digest=img_digest)
                    status, msg = t.run()
                    logger.info('Archive task result: status={}, detail={}'.format(status, msg))

                    if status == 'archived':
                        logger.info('Deleting source analysis for image {} after archiving'.format(img_digest))
                        if self.delete_source:
                            inputs = {
                                'method': 'DELETE',
                                'params': {'force': True},
                                'auth': ('',''),
                                'userId': self.account
                            }
                            with session_scope() as session:
                                resp, http_code = image_imageDigest(session, request_inputs=inputs, imageDigest=img_digest, bodycontent=None)
                                if http_code not in [200, 204]:
                                    logger.error('Could not delete image analysis: {}'.format(resp))
                                else:
                                    logger.info("Deleted image analysis for {} successfully".format(img_digest))
                else:
                    logger.info('Archive task DRY_RUN mode enabled via {}, would have archived image {}/{}'.format(DRY_RUN_ENV_VAR, self.account, img_digest))
            except Exception as ex:
                logger.exception('Caught unhandled exception in archive task')

    def _find_candidates(self, session: Session, rule: ArchiveTransitionRule):
        """
        Perform a match of the rule to an image based on any of its tags.

        For a match to occur, all specified criteria must be met: analysis time, tag selectors, and tag history

        Returns: list of tags or None.
        if the image does not match, return None
        if the image matches but has no tags, return empty list
        if the image has tags that match return list of those tags (may not be all the tags).
        :param session: session for db queries
        :param rule: ArchiveTransitionRule to process
        :return: list of tuples (CatalogImageDocer, CatalogImage) that match the rule
        """

        # Filter by analyzed_at timestamp first
        if rule.analysis_age_days >= 0:
            # Do analysis age check.
            min_time = int(time.time()) - (rule.analysis_age_days * 86400)
        else:
            min_time = 0

        if rule.selector_registry:
            registries = [rule.selector_registry]
        else:
            registries = None

        if rule.selector_repository:
            repositories = [rule.selector_repository]
        else:
            repositories = None

        if rule.selector_tag:
            tags = [rule.selector_tag]
        else:
            tags = None

        tag_histories_qry = db_catalog_image_docker.get_tag_histories(session, self.account, registries=registries, repositories=repositories, tags=tags)

        if min_time > 0:
            tag_histories_qry = tag_histories_qry.filter(CatalogImage.analyzed_at < min_time)

        return self._evaluate_tag_history(rule, tag_histories_qry)

    def _evaluate_tag_history(self, rule, image_tuple_generator):
        candidates = []
        current_tag = None
        history_depth = 0

        for tag_rec, image in image_tuple_generator:
            logger.debug('Checking tag: {}, image: {}'.format(tag_rec, image))
            if not current_tag:
                current_tag = tag_rec
                history_depth = 0

            if tag_rec.registry != current_tag.registry or tag_rec.repo != current_tag.repo or tag_rec.tag != current_tag.tag:
                #  No match, this is a new tag, so reset depth
                current_tag = tag_rec
                history_depth = 0

            # No depth required or at-or-beyond specified depth, the this is a candidate
            if rule.tag_versions_newer < 0 or rule.tag_versions_newer <= history_depth:
                candidates.append((tag_rec, image))

            history_depth += 1
            current_tag = tag_rec

        return candidates


class ArchivedAnalysisDeleter(ImageAnalysisArchiver):

    def run(self):
        with session_scope() as session:
            logger.debug('Running archive deletion rules')
            rules = session.query(ArchiveTransitionRule).filter_by(account=self.account, transition=ArchiveTransitions.delete).all()
            def lookup_archived_tags(account, digest):
                img = session.query(ArchivedImage).filter_by(account=account, imageDigest=digest).one_or_none()
                return img.tags()

            delete_merger = ArchiveTransitionTask.TagRuleMatchMerger(self.task_id, self.account, lookup_archived_tags)

            for rule in rules:
                matches = self._find_candidates(session, rule)
                logger.info('Rule: {} matches {}'.format(rule, matches))
                delete_merger.add_rule_result(rule, matches)

            to_delete = delete_merger.full_matched_digests()

        for img_digest in to_delete:
            logger.info('Archiving image {}/{}', self.account, img_digest)
            try:
                if not DRY_RUN_MODE:
                    t = DeleteArchivedImageTask(account=self.account, image_digest=img_digest, parent_task_id=self.task_id)
                    status, msg = t.run()
                    logger.info('Archive deletion task result: status={}, detail={}'.format(status, msg))
                else:
                    logger.info(
                        'Archive deletion task DRY_RUN mode enabled via {}, would have deleted archived image {}/{}'.format(
                            DRY_RUN_ENV_VAR, self.account, img_digest))
            except Exception as ex:
                logger.exception('Caught unhandled exception in archive deletion task')

    def _find_candidates(self, session: Session, rule: ArchiveTransitionRule):
        """
        Perform a match of the rule to an image based on any of its tags, but scanning the archived data set instead of the working ste.

        For a match to occur, all specified criteria must be met: analysis time, tag selectors, and tag history

        Returns: list of tags or None.
        if the image does not match, return None
        if the image matches but has no tags, return empty list
        if the image has tags that match return list of those tags (may not be all the tags).
        :param session: session for db queries
        :param rule: ArchiveTransitionRule to process
        :return: list of tuples (ArchivedImageDocker, ArchivedImage) that match the rule
        """

        # Filter by analyzed_at timestamp first
        if rule.analysis_age_days >= 0:
            # Do analysis age check.
            min_time = int(time.time()) - (rule.analysis_age_days * 86400)
        else:
            min_time = 0

        if rule.selector_registry:
            registries = [rule.selector_registry]
        else:
            registries = None

        if rule.selector_repository:
            repositories = [rule.selector_repository]
        else:
            repositories = None

        if rule.selector_tag:
            tags = [rule.selector_tag]
        else:
            tags = None

        tag_histories_qry = db_archived_images.get_tag_histories(session, self.account, registries=registries,
                                                                 repositories=repositories, tags=tags)

        if min_time > 0:
            tag_histories_qry = tag_histories_qry.filter(ArchivedImage.created_at < min_time)

        return self._evaluate_tag_history(rule, tag_histories_qry)


class ArchiveTransitionTask(object):
    """
    Task to find and transition images based on rules. Each task object is for all the rules in a given account.
    Executes sub-tasks for the archive and delete transitions individually

    Always runs archive transitions first, then delete transitions.

    """

    class TagRuleMatchMerger(object):
        """
        A tag merger for a single account.

        Aggregates the results from a set of rules and refines the results based on:
        * All tags for an image digest must match at least one rule for the image to be in the match set.


        """
        def __init__(self, task_id, account: str, image_tag_lookup_callback_fn: callable):
            """

            :param account:
            :param image_tag_lookup_callback_fn: Function to get the full set of tags for an account, imageDigest tuple. Called as image_tag_lookup_fn(account, digest). Returns a list of CatalogImageDocker or ArchivedImageDocker objects
            """
            self.task_id = task_id
            self.account = account
            self.tag_lookup_fn = image_tag_lookup_callback_fn
            self.image_tags_subset_matched = {} # Map image digests to the list of matched tags
            self.image_tags_full_match = {} # Map the image digests to their full tag sets, tracking that they are complete.
            self.image_tags = {} # Dict mapping image records to their full tag sets, where the image is partially matched

        def add_rule_result(self, rule, matched_tags):
            """
            Merge in the result to the current set.

            :param rule: the rule that was matched
            :param matches: list of CatalogImageDocker objects that match
            :return:
            """

            for tag, img in matched_tags:
                if tag.imageDigest not in self.image_tags_full_match:
                    if tag.imageDigest not in self.image_tags:
                        # Load the set of all tags for the image if this is the first encounter with that digest
                        full_tag_set = self.tag_lookup_fn(self.account, tag.imageDigest)
                        self.image_tags[tag.imageDigest] = full_tag_set

                    # Add the new tag to the list of already matched tags for the image
                    if tag.imageDigest in self.image_tags_subset_matched:
                        self.image_tags_subset_matched[tag.imageDigest].append(tag)
                    else:
                        self.image_tags_subset_matched[tag.imageDigest] = [tag]

                    if set(self.image_tags_subset_matched[tag.imageDigest]) == set(self.image_tags[tag.imageDigest]):
                        # Move the image to the other collection
                        self.image_tags_full_match[tag.imageDigest] = self.image_tags_subset_matched.pop(tag.imageDigest)
                        self.image_tags.pop(tag.imageDigest)
                else:
                    logger.info('Skipping tag {}'.format(tag))

        def full_matched_digests(self):
            """
            Return a list of image digests that have all of their tags matched by at least one rule

            :return:
            """

            return list(self.image_tags_full_match.keys())

    def __init__(self, account, parent_task_id=None):
        self.account = account
        self.task_id = uuid.uuid4().hex
        self.parent_task_id = parent_task_id

    def run(self):
        try:
            archiver = ImageAnalysisArchiver(self.account, self.parent_task_id, delete_source=True)
            archiver.run()
        except Exception as ex:
            logger.exception('Unhandled exception caught from analysis archiver')

        try:
            deleter = ArchivedAnalysisDeleter(self.account, self.parent_task_id)
            deleter.run()
        except Exception as ex:
            logger.exception('Unhandled exception caught from analysis archive deleter')


class LifecycleAction(object):
    def __init__(self, account, digest, tag, matched_rule):
        self.account = account
        self.digest = digest
        self.tag = tag
        self.src_rule = matched_rule


class DeleteArchivedImageTask(object):
    def __init__(self, account=None, image_digest=None, parent_task_id=None):
        self.initiated = datetime.datetime.utcnow()
        self.started = None
        self.stopped = None
        self.account = account
        self.image_digest = image_digest
        self.archive_record = None
        self.archive_detail_records = None
        self.parent_task_id = parent_task_id
        self.id = uuid.uuid4().hex

    def run(self):
        logger.debug("Starting archive deletion process for image {}".format(self.image_digest))
        self.started = datetime.datetime.utcnow()

        try:
            self._execute()
            add_event(ImageArchiveDeleted(self.account, self.image_digest, self.id))
        except Exception as err:
            logger.exception('Failed archive deletion execution')
            add_event(ImageArchiveDeleteFailed(self.account, self.image_digest, task_id=self.id, err=str(err)))
            raise
        finally:
            self.stopped = datetime.datetime.utcnow()

    def _execute(self):
        """
        Run the deletion of the archived data. This is irreversable.

        The final record delete (the ArchivedImage records) are deleted later with gc passes to leave them in the 'deleted' state
        for a while so users can see the transition.

        :return:
        """
        with session_scope() as session:
            rec = db_archived_images.get(session, self.account, self.image_digest)
            if not rec:
                raise MetadataNotFound('/'.join([self.account, self.image_digest]))

            self.archive_record = rec.to_dict()
            self.archive_detail_records = [x.to_dict() for x in rec.tags()]

        dest_archive_mgr = archive.get_manager()

        try:
            logger.debug('Deleting archive object: {}/{}'.format(self.archive_record['manifest_bucket'], self.archive_record['manifest_key']))
            dest_archive_mgr.delete(self.account, self.archive_record['manifest_bucket'], self.archive_record['manifest_key'])
            logger.debug('Image analysis archive deletion complete')
        except:
            logger.exception('Failure deleting archive content')
            raise

        with session_scope() as session:
            logger.debug('Deleting archive records for {}/{}'.format(self.account, self.image_digest))
            db_archived_images.delete(session, self.account, [self.image_digest])


class RestoreArchivedImageTask(object):
    """
    Task to load an archived image back into the working set for anchore

    """
    def __init__(self, account=None, image_digest=None, parent_task_id=None):
        self.id = uuid.uuid4().hex
        self.parent_id = parent_task_id
        self.initiated = datetime.datetime.utcnow()
        self.started = None
        self.stopped = None
        self.account = account
        self.image_digest = image_digest
        self.archive_record = None
        self.archive_tag_records = None

    def start(self):
        logger.debug("Starting archive restoration process for image {}".format(self.image_digest))
        self.started = datetime.datetime.utcnow()

        try:
            self._execute()
            logger.debug('Cleanly executed archive execute function')
            add_event(ImageRestored(self.account, self.image_digest))
        except:
            logger.exception('Error executing restore of image analysis from archive')
            add_event(ImageRestoreFailed(self.account, self.image_digest))
            raise
        finally:
            self.stopped = datetime.datetime.utcnow()

    def _execute(self):
        # if image record already exists, exit.

        with session_scope() as session:
            if db_catalog_image.get(self.image_digest, self.account, session):
                logger.info('Image archive restore found existing image records already. Aborting restore.')
                raise Exception('Conflict: Image already exists in system. No restore possible')

            rec = db_archived_images.get(session, self.account, self.image_digest)
            if not rec:
                raise MetadataNotFound('/'.join([str(self.account), str(self.image_digest)]))

            self.archive_record = rec.to_dict()
            self.archive_detail_records = [x.to_dict() for x in rec.tags()]

        src_archive_mgr = archive.get_manager()
        dest_obj_mgr = object_store.get_manager()

        # Load the archive manifest
        m = src_archive_mgr.get(self.account, self.archive_record['manifest_bucket'], self.archive_record['manifest_key'])

        if m:
            tf = tempfile.NamedTemporaryFile(prefix='analysis_archive_{}'.format(self.image_digest), dir=localconfig.get_config()['tmp_dir'], delete=False)
            try:
                tf.write(ensure_bytes(m))
                tf.close()

                # Load the archive from the temp file
                with ImageArchive.for_reading(tf.name) as img_archive:

                    logger.debug('Using manifest: {}'.format(img_archive.manifest))

                    self.restore_artifacts(img_archive, dest_obj_mgr)
                    self.restore_records(img_archive.manifest)
                    self._reload_policy_engine(img_archive.manifest)
            finally:
                os.remove(tf.name)

        else:
            raise Exception('No archive manifest found in archive record. Cannot restore')

    def restore_records(self, manifest: ArchiveManifest):
        """
        Re-create the catalog_image and catalog_image_docker records.

        :return:
        """
        with session_scope() as session:
            img_record_str = manifest.metadata.get('image_record')
            if not img_record_str:
                raise Exception('Cannot restore missing image record')
            else:
                img_record = json.loads(img_record_str)

            details = img_record.pop('image_detail')
            if not details:
                details = []

            c = CatalogImage()
            c.update(img_record)
            session.add(c)

            for detail in details:
                tr = CatalogImageDocker()
                tr.update(detail)
                session.add(tr)

        return True

    def restore_artifacts(self, img_archive: ImageArchive, dest_mgr: ObjectStorageManager) -> bool:
        """
        :return: tuple of (manifest (dict), bucket (str), key (str))
        """
        for artifact in img_archive.manifest.artifacts:
            if artifact.metadata and 'record' in artifact.metadata:
                record = artifact.metadata.get('record')
                r_type = artifact.metadata.get('record_type')
                if r_type == 'policy_evaluation':
                    try:
                        with session_scope() as session:
                            db_policyeval.add_all_for_digest([record], session)
                    except Exception as ex:
                        logger.warn('Could not insert records of type: {} due to exception: {}'.format(r_type, ex))
                        continue

            if artifact.source:
                logger.debug('Restoring artifact: {}'.format(artifact.name))

                data = img_archive.extract_artifact(artifact.name)

                if not data:
                    logger.error('Could not get data for {}'.format(artifact.name))
                    raise Exception('Archive data unavailable for {}'.format(artifact.name))

                logger.debug('Using: {}'.format(artifact.source))
                dest_mgr.put(self.account, artifact.source.bucket, artifact.source.key, ensure_bytes(data))

            else:
                logger.debug('Skipping load of archived data: {} due to no source information in manifest'.format(artifact.name))

        return True

    def _reload_policy_engine(self, manifest: ArchiveManifest) -> bool:
        logger.debug('Restoring image analysis into policy engine')

        try:
            pe_client = internal_client_for(PolicyEngineClient, userId=self.account)
            fetch_url = 'catalog://' + self.account + '/analysis_data/' + self.image_digest
            ingress_response = pe_client.ingress_image(self.account, manifest.metadata['image_id'], fetch_url)
            return ingress_response
        except Exception as ex:
            logger.exception("Error flushing policy engine state for image")
            raise ex


class ArchiveImageTask(object):
    """
    An archive task that moves an image and artifacts from archiving state to archived state.

    This task is a single unit-of-work for the db. It manages its own session.
    """

    __archive_bucket__ = 'analysis_archive'

    def __init__(self, account=None, image_digest=None, parent_task_id=None):
        self.id = uuid.uuid4().hex
        self.parent_task_id = parent_task_id

        self.account = account
        self.image_digest = image_digest
        self._result = None

        # Timestamps
        self.initiated = datetime.datetime.utcnow()
        self.started = None
        self.stopped = None

        self.manifest = None # Manifest to be saved and accessible outside of the tarball/backing-store lifecycle

        self.required_artifacts = [
            Artifact(name='analysis', source=ObjectStoreLocation(bucket='analysis_data', key=self.image_digest), dest=None, metadata={}),
            Artifact(name='image_content', source=ObjectStoreLocation(bucket='image_content_data', key=self.image_digest), dest=None, metadata={}),
            Artifact(name='image_manifest', source=ObjectStoreLocation(bucket='manifest_data', key=self.image_digest), dest=None, metadata={}),
        ]

        self._catalog_record = None

    def run(self, merge=False):
        """

        :param merge:
        :return: (str, str) tuple, with status as first element and detail msg as second
        """
        logger.debug("Starting archiving process for image {}".format(self.image_digest))

        self.started = datetime.datetime.utcnow()

        try:
            with session_scope() as session:
                found = db_archived_images.get(session, self.account, self.image_digest)
                if found and not merge:
                    # Short-circuit, since already exists
                    return found.status, 'Existing record found, archiving aborted'

                catalog_img_dict = db_catalog_image.get(self.image_digest, self.account, session)

                if not catalog_img_dict:
                    raise Exception('Could not locate an image with digest {} in account {}'.format(self.image_digest, self.account))
                else:
                    self._catalog_record = catalog_img_dict

                if catalog_img_dict.get('image_status') != 'active' or catalog_img_dict.get('analysis_status') != 'analyzed':
                    raise Exception('Invalid image record state. Image must have "analysis_status"="analyzed" and "image_status"="active". Found {} and {}'.format(catalog_img_dict.get('analysis_status'), catalog_img_dict.get('image_status')))

                # Add the new record
                img = ArchivedImage.from_catalog_image(catalog_img_dict, cascade=True)
                if merge and found:
                    img = session.merge(img)
                else:
                    img = session.add(img)

        except Exception as ex:
            add_event(ImageArchivingFailed(self.account, self.image_digest, self.id, err=str(ex)))
            return 'error', str(ex)

        try:
            return self._execute()
        except Exception as ex:
            logger.exception('Error executing image archive task')
            return 'error', str(ex)
        finally:
            self.stopped = datetime.datetime.utcnow()

    def _execute(self):
        """
        Do the archiving of data
        :return:
        """

        src_obj_mgr = object_store.get_manager()
        dest_archive_mgr = archive.get_manager()
        data_written = False

        with session_scope() as session:
            record = db_archived_images.get(session, self.account, self.image_digest)

            if not record:
                raise Exception('No analysis archive record found to track state')

            try:
                with tempfile.TemporaryDirectory(dir=localconfig.get_config().get('tmp_dir')) as tempdir:
                    with ImageArchive.for_writing(os.path.join(tempdir, 'analysis_archive.tar.gz')) as img_archive:
                        img_archive.account = self.account
                        img_archive.image_digest = self.image_digest

                        if self._catalog_record.get('image_detail'):
                            image_id = self._catalog_record.get('image_detail')[0]['imageId']
                        else:
                            image_id = None

                        img_archive.manifest.metadata = {
                            'versions': localconfig.get_versions(),
                            'image_id': image_id,
                            'image_record': json.dumps(self._catalog_record, sort_keys=True)
                        }

                        self.archive_required(src_obj_mgr, self.required_artifacts, img_archive)

                        try:
                            vuln_artifacts = self.archive_vuln_history(img_archive)
                        except:
                            logger.exception('Error saving vuln history')
                            raise

                        try:
                            eval_artifacts = self.archive_policy_evaluations(src_obj_mgr, img_archive, session)
                        except:
                            logger.exception('Error saving policy evals')
                            raise

                        self.manifest = img_archive.manifest

                    # Closed tarball, now write it.

                    archive_bucket = self.__archive_bucket__
                    archive_key = '{}.tar.gz'.format(self.image_digest)
                    record.manifest_bucket = archive_bucket
                    record.manifest_key = archive_key

                    # Write the archive out to object store
                    with open(img_archive.backing_file_path, 'r+b') as tb:
                        tarball_data = tb.read()
                        size = len(tarball_data)

                    if not dest_archive_mgr.put(self.account, bucket=archive_bucket, archiveId=archive_key, data=tarball_data):
                        raise Exception("Could not write archive manifest")

                    data_written = True
                    record.archive_size_bytes = size
                    record.status = 'archived'

                    return record.status, 'Completed successfully'

            except Exception as ex:
                record.status = 'error'

                if data_written:
                    logger.info('Cleaning up after failed analysis archive task for {}/{}'.format(self.account,
                                                                                                  self.image_digest))
                    try:
                        resp = dest_archive_mgr.delete(self.account, record.manifest_bucket, record.manifest_key)
                    except Exception as ex:
                        logger.warn('Could not delete the analysis archive tarball in storage. May have leaked. Err: {}'.format(ex))

                session.delete(record)
                return 'error', str(ex)

    def archive_required(self, src_mgr: ObjectStorageManager, artifacts: list, img_archive: ImageArchive) -> list:
        """

        :return: tuple of (manifest (dict), bucket (str), key (str))
        """
        for artifact in artifacts:
            data = src_mgr.get(self.account, artifact.source.bucket, artifact.source.key)

            if not data:
                raise Exception('Required artifact not found for migration: {}'.format(artifact.name))

            artifact.metadata['completed_at'] = datetime_to_rfc3339(datetime.datetime.utcnow())
            artifact.metadata['bytes_copied'] = len(data)
            artifact.dest = TarballLocation(tarfile_path=artifact.name)
            img_archive.add_artifact(artifact.name, source=artifact.source, data=data, metadata=artifact.metadata)

        return img_archive.manifest.artifacts

    def archive_policy_evaluations(self, src_obj_mgr: ObjectStorageManager, img_archive: ImageArchive, session) -> list:
        """
        Returns a dict of the following structure:
        {
          tag1 -> {policyId1 -> [eval history], policyId2 -> [eval history], ... },
          tag2 -> {policyId1...}, ... }
        }

        Policy evaluation histories are only moved, not generated, so online previously generated evaluations are migrated.

        :param dest_archive_mgr:
        :param dest_bucket:
        :return: dict mapping tags (full pull tags) to policy eval histories for the migrating image
        """

        logger.debug("Copying policy evaluation history to archive")

        policy_evaluations = db_policyeval.get_all_bydigest(self.account, self.image_digest, session)

        artifacts = []

        for eval_rec in policy_evaluations:
            artifact = Artifact(name='policy_evaluation-' + eval_rec['evalId'], metadata=None, source=None, dest=None)

            artifact.source = ObjectStoreLocation(bucket='policy_evaluations', key=eval_rec['evalId'])

            eval_content = src_obj_mgr.get(self.account, artifact.source.bucket, artifact.source.key)

            meta = {
                'record': eval_rec,
                'record_type': 'policy_evaluation',
                'completed_at': datetime_to_rfc3339(datetime.datetime.utcnow()),
                'bytes_copied': len(eval_content)
            }

            artifacts.append(artifact)
            img_archive.add_artifact(artifact.name, source=None, data=eval_content, metadata=meta)

        return artifacts

    def archive_vuln_history(self, img_archive: ImageArchive) -> list:
        logger.debug("Migrating image vulnerability history to archive")

        image_id = img_archive.manifest.metadata.get('image_id')
        if not image_id:
            logger.warn('No image id found in archive metadata for getting vuln history.')
            return []

        try:
            pe_client = internal_client_for(PolicyEngineClient, userId=self.account)
            vuln_report = pe_client.get_image_vulnerabilities(self.account, image_id)
            data = ensure_bytes(json.dumps(vuln_report, sort_keys=True))

            metadata = {'completed_at': datetime_to_rfc3339(datetime.datetime.utcnow()),
                        'bytes_copied': len(data)}

            a = img_archive.add_artifact('vulnerabilities', source=None, data=data, metadata=metadata)

            return [a]
        except Exception as ex:
            logger.exception("Error flushing policy engine state for image")
            raise ex

    # Removed since the archive task should not affect any sources
    # def flush_source_objects(self, src_mgr, artifacts):
    #     for artifact in artifacts:
    #         logger.debug('Flushing source artifact: {}'.format(artifact.name))
    #         if artifact.source and artifact.source.bucket:
    #             src_mgr.delete(self.account, artifact.source.bucket, artifact.source.key)
    #
    #     with session_scope() as session:
    #         db_catalog_image.delete(self.image_digest, self.account, session)
    #
    # def flush_policy_engine(self, image_id):
    #     try:
    #         pe_client = internal_client_for(PolicyEngineClient, userId=self.account)
    #         pe_client.delete_image(self.account, image_id)
    #     except Exception as ex:
    #         logger.exception("Error flushing policy engine state for image")
    #         raise ex
