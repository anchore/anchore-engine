"""
Functions for migrating between driver backends.

"""
import datetime
import json

from contextlib import contextmanager
import anchore_engine.db.entities.common
from anchore_engine.utils import get_threadbased_id
from anchore_engine.db import session_scope, ArchiveMetadata
from anchore_engine.db import ArchiveMigrationTask

from anchore_engine.subsys import logger
from anchore_engine.subsys import object_store
from anchore_engine.db.db_locks import db_application_lock, application_lock_ids

from .config import normalize_config
from .manager import ArchiveManager

from collections import namedtuple


MigrationContext = namedtuple('MigrationContext', field_names=['from_archive', 'to_archive'])


@contextmanager
def migration_context(from_archive_config, to_archive_config, do_lock=True):
    """
    Provides a context for upgrades including a lock on the db to ensure only one upgrade process at a time doing checks.

    Use a postgresql application lock to block schema updates and serialize checks
    :param lock_id: the lock id (int) for the lock to acquire
    :return:
    """

    logger.info('Initializing source archive: {}'.format(from_archive_config))
    from_archive = ArchiveManager(from_archive_config)

    logger.info('Initializing dest archive: {}'.format(to_archive_config))
    to_archive = ArchiveManager(to_archive_config)

    if do_lock:
        engine = anchore_engine.db.entities.common.get_engine()
        with db_application_lock(engine, (application_lock_ids['archive_migration']['namespace'], application_lock_ids['archive_migration']['ids']['default'])):
            yield MigrationContext(from_archive=from_archive, to_archive=to_archive)
    else:
        yield MigrationContext(from_archive=from_archive, to_archive=to_archive)


def initiate_migration(from_config, to_config, remove_on_source=False, do_lock=True):
    """
    Start a migration operation from one config to another, with optionally removing the data on the source and optionally using a global lock.

    Expects the input configs to be already validated and normalized.

    :param from_config:
    :param to_config:
    :param remove_on_source:
    :param do_lock:
    :return:
    """

    logger.info('Initializing migration from {} to {}'.format(from_config, to_config))


    with migration_context(from_config, to_config, do_lock=do_lock) as context:
        with session_scope() as db:
            # Load all metadata
            to_migrate = [(record.userId, record.bucket, record.archiveId, record.content_url) for record in db.query(ArchiveMetadata).filter(ArchiveMetadata.content_url.like(context.from_archive.primary_client.__uri_scheme__ + '://%'))]

            task_record = ArchiveMigrationTask()
            task_record.archive_documents_to_migrate = len(to_migrate)
            task_record.archive_documents_migrated = 0
            task_record.migrate_from_driver = context.from_archive.primary_client.__config_name__
            task_record.migrate_to_driver = context.to_archive.primary_client.__config_name__
            task_record.state = 'running'
            task_record.started_at = datetime.datetime.utcnow()

            task_record.executor_id = get_threadbased_id()

            db.add(task_record)
            db.flush()
            task_id = task_record.id
            logger.info('Migration Task Id: {}'.format(task_id))

        logger.info('Entering main migration loop')
        logger.info('Migrating {} documents'.format(len(to_migrate)))
        counter = 0
        result_state = 'failed'

        try:
            for (userId, bucket, archiveId, content_url) in to_migrate:
                # content_url = None

                try:
                    # Use high-level archive operations to ensure compression etc are updated appropriately
                    data = context.from_archive.get(userId, bucket, archiveId)
                    context.to_archive.put(userId, bucket, archiveId, data)


                #     with session_scope() as db:
                #         record = db.query(ArchiveMetadata).filter(ArchiveMetadata.userId == rec_tuple[0], ArchiveMetadata.bucket == rec_tuple[1], ArchiveMetadata.archiveId == rec_tuple[2]).first()
                #         if not record:
                #             logger.warn('No record found in db for: {}'.format(rec_tuple))
                #             continue
                #
                #         if not record.content_url.startswith(context.from_client.__uri_scheme__ + '://'):
                #             logger.warn('Initial query returned content url: {} but migration query found url {}. Skipping.'.format(rec_tuple[4], record.content_url))
                #             continue
                #
                #         logger.info('Migrating document {}/{}/{} -- current uri: {}'.format(record.userId, record.bucket, record.archiveId, record.content_url))
                #         content_url = record.content_url
                #         loaded = context.from_client.get_by_uri(record.content_url)
                #         record.content_url = context.to_client.put(record.userId, record.bucket, record.archiveId, loaded)
                #         logger.info('Migrated document {}/{}/{} -- from {} to {}'.format(record.userId, record.bucket, record.archiveId, content_url, record.content_url))
                #
                #         # Should be the most recent/highest id task
                #         task_record = db.merge(task_record)
                #         task_record.archive_documents_migrated += 1
                #         counter = task_record.archive_documents_migrated
                #
                    if remove_on_source:
                        if context.from_archive.primary_client.__config_name__ != context.to_archive.primary_client.__config_name__:
                            logger.info('Deleting document on source after successful migration to destination. Src = {}'.format(content_url))
                            # Only delete after commit is complete
                            try:
                                context.from_archive.primary_client.delete_by_uri(content_url)
                            except Exception as e:
                                logger.exception('Error cleaning up old record with uri: {}. Aborting migration'.format(content_url))
                                raise
                        else:
                            logger.info('Skipping removal of documents on source because source and dest drivers are the same')
                    else:
                        logger.info('Skipping removal of document on source driver because configured to leave source data.')
                    counter = counter + 1
                except Exception as e:
                    logger.exception('Error migrating content url: {} to {}'.format(content_url, context.from_archive.primary_client.__config_name__, context.to_archive.primary_client.__config_name__,))
            else:
                result_state = 'complete'

        finally:
            with session_scope() as db:
                db.add(task_record)
                db.refresh(task_record)
                task_record.last_state = task_record.state
                task_record.state = result_state
                task_record.ended_at = datetime.datetime.utcnow()
                task_record.archive_documents_migrated = counter
                logger.info('Migration result summary: {}'.format(json.dumps(task_record.to_json())))


