"""
Long running tasks
"""

import json
import datetime
import time
import requests
import urllib
import dateutil.parser

from sqlalchemy.exc import IntegrityError
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds, InsufficientAccessTierError, InvalidCredentialsError
from anchore_engine.db import get_thread_scoped_session as get_session, Image
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.loaders import ImageLoader
from anchore_engine.services.policy_engine.engine.exc import *
from anchore_engine.services.policy_engine.engine.vulnerabilities import vulnerabilities_for_image, find_vulnerable_image_packages, ImagePackageVulnerability
from anchore_engine.clients import catalog

# A hack to get admin credentials for executing api ops
from anchore_engine.services.catalog import db_users
from anchore_engine.db import session_scope

log = get_logger()

def construct_task_from_json(json_obj):
    """
    Given a json object, build an AsyncTask to execute.

    :param json_obj: the json to process
    :return: an AsynTask object
    """
    if not json_obj.get('type'):
        raise ValueError('Cannot determine task type from content')

    task = IAsyncTask.tasks[json_obj['type']].from_json(json_obj)
    log.info('Mapped to task type: {}'.format(task.__class__))
    return task


class AsyncTaskMeta(type):
    """
    A parent meta type that maintains a task type registry for mapping incoming tasks to the class to process them.
    """
    def __init__(cls, name, bases, dct):
        super(AsyncTaskMeta, cls).__init__(name, bases, dct)
        if not hasattr(cls,'tasks'):
            cls.tasks = {}
        elif '__task_name__' in dct:
            cls.tasks[dct['__task_name__']] = cls


class IAsyncTask(object):
    """
    Base type for async tasks to ensure they are in the task registry and implement the basic interface.

    Async tasks are expected to be completely self-contained including any db session management. They have
    complete control over the db session.

    """
    __metaclass__ = AsyncTaskMeta

    __task_name__ = None

    def execute(self):
        raise NotImplementedError()


class DispatchableTaskMixin(object):
    """
    A mixin class for making a task class symmetric in that it can dispatch itself to the queue upon construction.
    Allows for a flow where the synchronous portion of the system can construct the appropriate task class for an external
    request and dispatch it to the backend workers using the same type that the backend workers will parse and construct.
    The symmetry ensures clean encode/decode operations on updates.

    """
    #__task_queue__ = boto3.resource('sqs', region_name='us-west-2').get_queue_by_name(QueueName='kirk-tasks')

    def dispatch(self):
        return
        # try:
        #     self.__task_queue__.send_message(body=self.json())
        #
        # except:
        #     log.exception('Failure to dispatch the request to the async task queue {}'.format(self.__task_queue__.name))
        #     raise

    def json(self):
        """
        The json representation of this task as it will be encoded in the message.
        :return:
        """
        raise NotImplementedError()


class EchoTask(IAsyncTask, DispatchableTaskMixin):
    """
    A simple echo task for testing an runtime performance checks
    """

    __task_name__ = 'echo'

    def __init__(self, message):
        self.msg = message

    def json(self):
        return {
            'type': self.__task_name__,
            'message': self.msg
        }

    @classmethod
    def from_json(cls, json_obj):
        if json_obj.get('type') != cls.__task_name__:
            raise ValueError('Wrong task type')
        t = EchoTask(json_obj['message'])
        return t

    def execute(self):
        log.info('Executing ECHO task!')
        log.info('Message: {}'.format(self.msg))
        return


class FeedsUpdateTask(IAsyncTask, DispatchableTaskMixin):
    """
    Scan and sync all configured and available feeds to ensure latest state.

    Task is expected to have full control of db session and will commit/rollback as needed.
    """

    __task_name__ = 'feed_update'

    def __init__(self, feed=None, group=None, created_at=None):
        self.feed = feed
        self.group = group
        self.received_at = None
        self.created_at = created_at

    def is_full_sync(self):
        return self.feed is None

    def is_group_sync(self):
        return self.feed is not None and self.group is not None

    def execute(self):
        log.info('Starting feed update')
        try:
            updated = []
            if self.is_full_sync():
                updated_dict = self._full_sync()
                for g in updated_dict:
                    updated += updated_dict[g]
            elif self.is_group_sync():
                df = DataFeeds.instance()
                if self.feed == 'vulnerabilities':
                    log.info('Performing vulnerability sync only')
                    v = df.vulnerabilities
                    updated = v.sync(group=self.group, item_processing_fn=self.process_updated_vulnerability)
                    log.info('Updated vulnerabilities. {} images updated.'.format(len(updated) if updated else 'unknown'))

                elif self.feed == 'packages':
                   updated = df.packages.sync(group=self.group)
                   log.info('Synced {} packages'.format(len(updated) if updated else 'unknown'))
                else:
                   raise ValueError('Unknown feed name: {}'.format(self.feed))
            return updated
        except:
            log.exception('Failure refreshing and syncing feeds')
            raise

    def _full_sync(self):
        """
        Sync all the feeds and groups.

        :return: dict of cve group names mapped to lists of images updated during the sync for each group
        """

        try:
            log.info('Executing full sync')
            df = DataFeeds.instance()

            log.info('Executing vulnerability feed sync')
            vuln_updates = {}
            try:
                # Update the vulnerabilities with updates to the affected images done within the same transaction scope
                vuln_updates = df.vulnerabilities.sync(item_processing_fn=FeedsUpdateTask.process_updated_vulnerability)
                group_counts = [len(grp_updates) for grp_updates in vuln_updates.values()]
                total_count = reduce(lambda x, y: x + y, group_counts, 0)
                log.info('Processed {} vulnerability updates in {} groups'.format(total_count, len(group_counts)))
            except InvalidCredentialsError as e:
                log.error('Configured credentials are invalid. Either fix configuration or use anonymous credentials')

            try:
                log.info('Executing package feed sync')
                df.packages.sync()
            except InsufficientAccessTierError as e:
                log.warn('Skipping sync of packages feed due to insufficient privileges of user. Msg: {}'.format(e.message))

            return vuln_updates
        except:
            log.exception('Failure processing updates for feeds')
            raise

    @staticmethod
    def process_updated_vulnerability(db, vulnerability):
        """
        Update vulnerability matches for this vulnerability. This function will add objects to the db session but
        will not commit. The caller is expected to manage the session lifecycle.

        :param: item: The updated vulnerability object
        :param: db: The db session to use, should be valid and open
        :return: list of (user_id, image_id) that were affected
        """
        log.debug('Processing CVE update for: {}'.format(vulnerability.id))
        changed_images = []

        # Find any packages already matched with the CVE ID.
        current_affected = vulnerability.current_package_vulnerabilities(db)

        # May need to remove vuln from some packages.
        if vulnerability.is_empty():
            log.debug('Detected an empty CVE. Removing all existing matches on this CVE')

            # This is a flush, nothing can be vulnerable to this, so remove it from packages.
            if current_affected:
                log.debug('Detected {} existing matches on CVE {} to remove'.format(len(current_affected), vulnerability.id))

                for pkgVuln in current_affected:
                    log.debug('Removing match on image: {}/{}'.format(pkgVuln.pkg_user_id, pkgVuln.pkg_image_id))
                    db.delete(pkgVuln)
                    changed_images.append((pkgVuln.pkg_user_id, pkgVuln.pkg_image_id))
        else:
            # Find impacted images for the current vulnerability
            new_vulnerable_packages = [ImagePackageVulnerability.from_pair(x, vulnerability) for x in find_vulnerable_image_packages(vulnerability)]
            unique_vuln_pkgs = set(new_vulnerable_packages)
            current_match = set(current_affected)

            if len(new_vulnerable_packages) > 0:
                log.debug('Found {} packages vulnerable to cve {}'.format(len(new_vulnerable_packages), vulnerability.id))
                log.debug('Dedup matches from {} to {}'.format(len(new_vulnerable_packages), len(unique_vuln_pkgs)))

            # Find the diffs of any packages that were vulnerable but are no longer.
            no_longer_affected = current_match.difference(unique_vuln_pkgs)
            possibly_updated = current_match.intersection(unique_vuln_pkgs)
            new_matches = unique_vuln_pkgs.difference(current_match)

            if len(no_longer_affected) > 0:
                log.debug('Found {} packages no longer vulnerable to cve {}'.format(len(no_longer_affected), vulnerability.id))
                for img_pkg_vuln in no_longer_affected:
                    log.debug('Removing old invalid match for pkg {} on cve {}'.format(img_pkg_vuln, vulnerability.id))
                    db.delete(img_pkg_vuln)
                db.flush()

            for v in new_matches:
                log.debug('Adding new vulnerability match: {}'.format(v))
                db.add(v)
                changed_images.append((v.pkg_user_id, v.pkg_image_id))

            db.flush()
        log.info('Images changed for cve {}: {}'.format(vulnerability.id, changed_images))
        return changed_images

    @classmethod
    def from_json(cls, json_obj):
        if not json_obj['type'] == cls.__task_name__:
            raise ValueError('Specified json is not for this message type: {} != {}'.format(json_obj.get('type'), cls.__task_name__))

        task = FeedsUpdateTask(feed=json_obj.get('feed'), group=json_obj.get('group'), created_at=json_obj.get('created_at'))
        task.received_at = datetime.datetime.utcnow()
        return task


class ImageLoadResult(object):
    def __init__(self, img, vulnerabilities):
        self.loaded_img_obj = img
        self.img_vulnerabilities = vulnerabilities


class ImageLoadTask(IAsyncTask, DispatchableTaskMixin):
    """
    A stateful task for loading image analysis.

    This task is a session boundary and expects full control of a session during execution.
    """

    __task_name__ = 'image_load'

    analysis_keys = [
        'full_analyzers',
        'full_analysis',
        'full_analyzer'
    ]

    __loader_class__ = ImageLoader

    def __init__(self, user_id, image_id, url=None):
        self.image_id = image_id
        self.user_id = user_id
        self.start_time = None
        self.stop_time = None
        self.fetch_url = url
        self.session = None,
        self.received_at = None,
        self.created_at = datetime.datetime.utcnow()

    def json(self):
        return {
            'type': self.__task_name__,
            'user_id': self.user_id,
            'image_id': self.image_id,
            'url': self.fetch_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'received_at': self.received_at.isoformat() if self.received_at else None
        }

    @classmethod
    def from_json(cls, json_obj):
        if json_obj.get('type') != cls.__task_name__:
            raise ValueError('Specified json is not for this message type')

        img = ImageLoadTask(json_obj['user_id'], json_obj['image_id'], url=json_obj.get('url'))
        img.created_at = dateutil.parser.parse(json_obj['created_at'])
        img.received_at = datetime.datetime.utcnow()
        return img

    def execute(self):
        """
        Execute a load.
        Fetch from the catalog and send to loader.
        :return: the ImageLoad result object including the image object and its vulnerabilities or None if image already found
        """

        self.start_time = datetime.datetime.utcnow()
        try:
            db = get_session()
            img = db.query(Image).get((self.image_id, self.user_id))
            if img is not None:
                log.info('Image {}/{} already found in the system. Will not re-load.'.format(self.user_id, self.image_id))
                db.close()
                return None

            # Close the session during the data fetch.
            db.close()

            image_obj = self._load_image_analysis()
            if not image_obj:
                log.error('Could not load image analysis')
                raise ImageLoadError('Failed to load image: user_id = {}, image_id = {}, fetch_url = {}'.format(self.user_id, self.image_id, self.fetch_url))

            db = get_session()
            try:
                log.info("Adding image to db")
                db.add(image_obj)

                log.info("Adding image package vulnerabilities to db")
                vulns = vulnerabilities_for_image(image_obj)
                for vuln in vulns:
                    db.add(vuln)

                db.commit()
            except:
                log.exception('Error adding image to db')
                db.rollback()
                raise

            return ImageLoadResult(image_obj, vulns)
        except Exception as e:
            log.exception('Error loading and scanning image: {}'.format(self.image_id))
            raise
        finally:
            self.stop_time = datetime.datetime.utcnow()

    def _load_image_analysis(self):
        """
        Get the image analysis data content itself from either the url provided or check the catalog.

        :return:
        """
        log.info('Loading image analysis for image: {}/{}'.format(self.user_id, self.image_id))

        if not self.fetch_url:
            log.info('No url provided, cannot proceed!')
            raise ValueError('No fetch url provided')

        log.info('Fetching analysis with url: {}'.format(self.fetch_url))
        content = self._get_content(self.fetch_url)

        try:
            loader = self.__loader_class__(content)
            result = loader.load()
            if result.id != self.image_id:
                raise ValueError('Image ID found in analysis report does not match requested id. {} != {}'.format(result.id, self.image_id))

            result.user_id = self.user_id
            return result
        except KeyError as e:
            log.exception('Could not locate key in image analysis data that is required: {}'.format(e))
            raise
        except Exception as e:
            log.exception('Exception in image loader')
            raise

    def _get_content(self, url):
        """
        This can be *big*, as in hundreds of MB of data.

        Supported url formats:
        file://
        http(s)://
        catalog://<userId>/<bucket>/<name>

        :param url: 
        :return: 
        """

        split_url = urllib.splittype(url)
        if split_url[0] == 'file':
            return self._get_file(split_url[1])
        elif split_url[0] == 'catalog':
            userId, bucket, name = split_url[1][2:].split('/')

            # Add auth if necessary
            try:
                with session_scope() as dbsession:
                    usr_record = db_users.get('admin', session=dbsession)
                if not usr_record:
                    raise Exception('User {} not found, cannot fetch analysis data'.format('admin'))
            except:
                log.exception('Cannot get admin credentials for fetching the analysis content to load')
                raise
            try:
                doc = catalog.get_document((usr_record['userId'], usr_record['password']), bucket, name)
                return doc
            except:
                log.exception('Error retrieving analysis json from the catalog service')
                raise

        elif split_url[0].startswith('http'):
            retry = 3
            while retry > 0:
                try:
                    data_response = requests.get(url=url)
                    content = data_response.json()
                    return content
                except requests.HTTPError as ex:
                    log.exception('HTTP exception: {}. Retrying'.format(ex))
                    retry = retry - 1
                    time.sleep(retry * 3)  # Backoff and retry
                except:
                    log.exception('Non HTTP exception. Retrying')
                    retry = retry - 1

        else:
            raise Exception('Cannot get content from url: {}'.format(url))

    def _get_file(self, path):
        with open(path) as r:
            return json.load(r)
