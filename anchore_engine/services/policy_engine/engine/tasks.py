"""
Long running tasks
"""

import json
import datetime
import dateutil.parser
import requests
import time
import urllib.request, urllib.parse, urllib.error
import uuid

from anchore_engine.db import (
    get_thread_scoped_session as get_session,
    Image,
    end_session,
)
from anchore_engine.services.policy_engine.engine.loaders import ImageLoader
from anchore_engine.services.policy_engine.engine.exc import *
from anchore_engine.services.policy_engine.engine.vulnerabilities import (
    vulnerabilities_for_image,
    rescan_image,
)

from anchore_engine.clients.services.catalog import CatalogClient
from anchore_engine.clients.services import internal_client_for
from anchore_engine.services.policy_engine.engine.feeds.sync import (
    get_selected_feeds_to_sync,
    DataFeeds,
)
from anchore_engine.services.policy_engine.engine.feeds.feeds import notify_event
from anchore_engine.configuration import localconfig
from anchore_engine.clients.services.simplequeue import run_target_with_lease
from anchore_engine.subsys.events import (
    FeedSyncTaskStarted,
    FeedSyncTaskCompleted,
    FeedSyncTaskFailed,
)
from anchore_engine.subsys import identities, logger

# A hack to get admin credentials for executing api ops
from anchore_engine.db import session_scope


def construct_task_from_json(json_obj):
    """
    Given a json object, build an AsyncTask to execute.

    :param json_obj: the json to process
    :return: an AsynTask object
    """
    if not json_obj.get("type"):
        raise ValueError("Cannot determine task type from content")

    task = IAsyncTask.tasks[json_obj["type"]].from_json(json_obj)
    logger.info("Mapped to task type: {}".format(task.__class__))
    return task


class AsyncTaskMeta(type):
    """
    A parent meta type that maintains a task type registry for mapping incoming tasks to the class to process them.
    """

    def __init__(cls, name, bases, dct):
        super(AsyncTaskMeta, cls).__init__(name, bases, dct)
        if not hasattr(cls, "tasks"):
            cls.tasks = {}
        elif "__task_name__" in dct:
            cls.tasks[dct["__task_name__"]] = cls


class IAsyncTask(object, metaclass=AsyncTaskMeta):
    """
    Base type for async tasks to ensure they are in the task registry and implement the basic interface.

    Async tasks are expected to be completely self-contained including any db session management. They have
    complete control over the db session.

    """

    __task_name__ = None

    def execute(self):
        raise NotImplementedError()


class EchoTask(IAsyncTask):
    """
    A simple echo task for testing an runtime performance checks
    """

    __task_name__ = "echo"

    def __init__(self, message):
        self.msg = message

    def json(self):
        return {"type": self.__task_name__, "message": self.msg}

    @classmethod
    def from_json(cls, json_obj):
        if json_obj.get("type") != cls.__task_name__:
            raise ValueError("Wrong task type")
        t = EchoTask(json_obj["message"])
        return t

    def execute(self):
        logger.info("Executing ECHO task!")
        logger.info("Message: {}".format(self.msg))
        return


class FeedsFlushTask(IAsyncTask):
    """
    A task that only flushes feed data, not resyncs

    """

    def execute(self):
        raise NotImplementedError()

        # db = get_session()
        # try:
        #     count = db.query(ImagePackageVulnerability).delete()
        #     log.info('Deleted {} vulnerability match records in flush'.format(count))
        #     f = DataFeeds.instance()
        #     f.flush()
        #     db.commit()
        # except:
        #     log.exception('Error executing feeds flush task')
        #     raise


class FeedsUpdateTask(IAsyncTask):
    """
    Scan and sync all configured and available feeds to ensure latest state.

    Task is expected to have full control of db session and will commit/rollback as needed.
    """

    __task_name__ = "feed_sync"
    locking_enabled = True

    @classmethod
    def run_feeds_update(cls, json_obj=None, force_flush=False):
        """
        Creates a task and runs it, optionally with a thread if locking is enabled.

        :return:
        """
        feeds = None

        try:

            feeds = get_selected_feeds_to_sync(localconfig.get_config())
            if json_obj:
                task = cls.from_json(json_obj)
                if not task:
                    return None
                task.feeds = feeds
            else:
                task = FeedsUpdateTask(feeds_to_sync=feeds, flush=force_flush)

            result = []
            if cls.locking_enabled:
                run_target_with_lease(
                    account=None,
                    lease_id="feed_sync",
                    ttl=90,
                    target=lambda: result.append(task.execute()),
                )
                # A bit of work-around for the lambda def to get result from thread execution
                if result:
                    result = result[0]
            else:
                result = task.execute()

            return result
        except Exception:
            logger.exception("Error executing feeds update")
            raise

    def __init__(self, feeds_to_sync=None, flush=False):
        self.feeds = feeds_to_sync
        self.created_at = datetime.datetime.utcnow()
        self.full_flush = flush
        self.uuid = uuid.uuid4().hex

    def is_full_sync(self):
        return self.feeds is None

    def execute(self):
        logger.info("Starting feed sync. (operation_id={})".format(self.uuid))

        # Feed syncs will update the images with any new cves that are pulled in for a the sync. As such, any images that are loaded while the sync itself is in progress need to be
        # re-scanned for cves since the transaction ordering can result in the images being loaded with data prior to sync but not included in the sync process itself.

        # Create feed task begin event
        error = None
        with session_scope() as session:
            mgr = identities.manager_factory.for_session(session)
            catalog_client = internal_client_for(CatalogClient, userId=None)

        try:
            notify_event(
                FeedSyncTaskStarted(groups=self.feeds if self.feeds else "all"),
                catalog_client,
                self.uuid,
            )
        except:
            logger.exception(
                "Ignoring event generation error before feed sync. (operation_id={})".format(
                    self.uuid
                )
            )

        start_time = datetime.datetime.utcnow()
        try:
            start_time = datetime.datetime.utcnow()
            updated_dict = DataFeeds.sync(
                to_sync=self.feeds,
                full_flush=self.full_flush,
                catalog_client=catalog_client,
                operation_id=self.uuid,
            )

            logger.info("Feed sync complete (operation_id={})".format(self.uuid))
            return updated_dict
        except Exception as e:
            error = e
            logger.exception(
                "Failure refreshing and syncing feeds. (operation_id={})".format(
                    self.uuid
                )
            )
            raise
        finally:
            end_time = datetime.datetime.utcnow()
            # log feed sync event
            try:
                if error:
                    notify_event(
                        FeedSyncTaskFailed(
                            groups=self.feeds if self.feeds else "all", error=error
                        ),
                        catalog_client,
                        self.uuid,
                    )
                else:
                    notify_event(
                        FeedSyncTaskCompleted(
                            groups=self.feeds if self.feeds else "all"
                        ),
                        catalog_client,
                        self.uuid,
                    )
            except:
                logger.exception(
                    "Ignoring event generation error after feed sync (operation_id={})".format(
                        self.uuid
                    )
                )

            try:
                self.rescan_images_created_between(
                    from_time=start_time, to_time=end_time
                )
            except:
                logger.exception(
                    "Unexpected exception rescanning vulns for images added during the feed sync. (operation_id={})".format(
                        self.uuid
                    )
                )
                raise
            finally:
                end_session()

    def rescan_images_created_between(self, from_time, to_time):
        """
        If this was a vulnerability update (e.g. timestamps vuln feeds lies in that interval), then look for any images that were loaded in that interval and
        re-scan the cves for those to ensure that no ordering of transactions caused cves to be missed for an image.

        This is an alternative to a blocking approach by which image loading is blocked during feed syncs.

        :param from_time:
        :param to_time:
        :return: count of updated images
        """

        if from_time is None or to_time is None:
            raise ValueError("Cannot process None timestamp")

        logger.info(
            "Rescanning images loaded between {} and {} (operation_id={})".format(
                from_time.isoformat(), to_time.isoformat(), self.uuid
            )
        )
        count = 0

        db = get_session()
        try:
            # it is critical that these tuples are in proper index order for the primary key of the Images object so that subsequent get() operation works
            imgs = [
                (x.id, x.user_id)
                for x in db.query(Image).filter(
                    Image.created_at >= from_time, Image.created_at <= to_time
                )
            ]
            logger.info(
                "Detected images: {} for rescan (operation_id={})".format(
                    " ,".join([str(x) for x in imgs]) if imgs else "[]", self.uuid
                )
            )
        finally:
            db.rollback()

        retry_max = 3
        for img in imgs:
            for i in range(retry_max):
                try:
                    # New transaction for each image to get incremental progress
                    db = get_session()
                    try:
                        # If the type or ordering of 'img' tuple changes, this needs to be updated as it relies on symmetry of that tuple and the identity key of the Image entity
                        image_obj = db.query(Image).get(img)
                        if image_obj:
                            logger.info(
                                "Rescanning image {} post-vuln sync. (operation_id={})".format(
                                    img, self.uuid
                                )
                            )
                            vulns = rescan_image(image_obj, db_session=db)
                            count += 1
                        else:
                            logger.warn(
                                "Failed to lookup image with tuple: {} (operation_id={})".format(
                                    str(img), self.uuid
                                )
                            )

                        db.commit()

                    finally:
                        db.rollback()

                    break
                except Exception as e:
                    logger.exception(
                        "Caught exception updating vulnerability scan results for image {}. Waiting and retrying (operation_id={})".format(
                            img, self.uuid
                        )
                    )
                    time.sleep(5)

        return count

    @classmethod
    def from_json(cls, json_obj):
        if not json_obj.get("task_type") == cls.__task_name__:
            raise ValueError(
                "Specified json is not for this message type: {} != {}".format(
                    json_obj.get("task_type"), cls.__task_name__
                )
            )

        if not json_obj.get("enabled", False):
            return None

        task = FeedsUpdateTask()
        task.received_at = datetime.datetime.utcnow()
        return task


class ImageLoadResult(object):
    def __init__(self, img, vulnerabilities):
        self.loaded_img_obj = img
        self.img_vulnerabilities = vulnerabilities


class ImageLoadTask(IAsyncTask):
    """
    A stateful task for loading image analysis.

    This task is a session boundary and expects full control of a session during execution.
    """

    __task_name__ = "image_load"

    analysis_keys = ["full_analyzers", "full_analysis", "full_analyzer"]

    __loader_class__ = ImageLoader

    def __init__(
        self,
        user_id,
        image_id,
        url=None,
        force_reload=False,
        content_conn_timeout=None,
        content_read_timeout=None,
    ):
        self.image_id = image_id
        self.user_id = user_id
        self.start_time = None
        self.stop_time = None
        self.fetch_url = url
        self.session = (None,)
        self.received_at = (None,)
        self.created_at = datetime.datetime.utcnow()
        self.force_reload = force_reload
        self.content_conn_timeout = content_conn_timeout
        self.content_read_timeout = content_read_timeout

    def json(self):
        return {
            "type": self.__task_name__,
            "user_id": self.user_id,
            "image_id": self.image_id,
            "url": self.fetch_url,
            "force_reload": self.force_reload,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "received_at": self.received_at.isoformat() if self.received_at else None,
        }

    @classmethod
    def from_json(cls, json_obj):
        if json_obj.get("type") != cls.__task_name__:
            raise ValueError("Specified json is not for this message type")

        img = ImageLoadTask(
            json_obj["user_id"],
            json_obj["image_id"],
            url=json_obj.get("url"),
            force_reload=json_obj.get("force_reload"),
        )
        img.created_at = dateutil.parser.parse(json_obj["created_at"])
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
                if not self.force_reload:
                    logger.info(
                        "Image {}/{} already found in the system. Will not re-load.".format(
                            self.user_id, self.image_id
                        )
                    )
                    db.close()
                    return None
                else:
                    logger.info(
                        "Deleting image {}/{} and all associated resources for reload".format(
                            self.user_id, self.image_id
                        )
                    )
                    for pkg_vuln in img.vulnerabilities():
                        db.delete(pkg_vuln)
                    db.delete(img)

            # Close the session during the data fetch.
            # db.close()

            image_obj = self._load_image_analysis()
            if not image_obj:
                logger.error("Could not load image analysis")
                raise ImageLoadError(
                    "Failed to load image: user_id = {}, image_id = {}, fetch_url = {}".format(
                        self.user_id, self.image_id, self.fetch_url
                    )
                )

            db = get_session()
            try:
                logger.info("Adding image to db")
                db.add(image_obj)

                ts = time.time()
                logger.info("Adding image package vulnerabilities to db")
                vulns = vulnerabilities_for_image(image_obj)
                for vuln in vulns:
                    db.add(vuln)

                db.commit()
                # log.debug("TIMER TASKS: {}".format(time.time() - ts))
            except:
                logger.exception("Error adding image to db")
                db.rollback()
                raise

            return ImageLoadResult(image_obj, vulns)
        except Exception as e:
            logger.exception(
                "Error loading and scanning image: {}".format(self.image_id)
            )
            raise
        finally:
            self.stop_time = datetime.datetime.utcnow()

    def _load_image_analysis(self):
        """
        Get the image analysis data content itself from either the url provided or check the catalog.

        :return:
        """
        logger.info(
            "Loading image analysis for image: {}/{}".format(
                self.user_id, self.image_id
            )
        )

        if not self.fetch_url:
            logger.info("No url provided, cannot proceed!")
            raise ValueError("No fetch url provided")

        logger.info("Fetching analysis with url: {}".format(self.fetch_url))
        content = self._get_content(self.fetch_url)

        try:
            loader = self.__loader_class__(content)
            result = loader.load()
            if result.id != self.image_id:
                raise ValueError(
                    "Image ID found in analysis report does not match requested id. {} != {}".format(
                        result.id, self.image_id
                    )
                )

            result.user_id = self.user_id
            return result
        except KeyError as e:
            logger.exception(
                "Could not locate key in image analysis data that is required: {}".format(
                    e
                )
            )
            raise
        except Exception as e:
            logger.exception("Exception in image loader")
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

        split_url = urllib.parse.splittype(url)
        if split_url[0] == "file":
            path = split_url[1][2:]  # Strip the leading '//'
            return self._get_file(path)
        elif split_url[0] == "catalog":
            userId, bucket, name = split_url[1][2:].split("/")

            # Add auth if necessary
            try:
                catalog_client = internal_client_for(CatalogClient, userId)
                with catalog_client.timeout_context(
                    self.content_conn_timeout, self.content_read_timeout
                ) as timeout_client:
                    doc = timeout_client.get_document(bucket, name)
                return doc
            except:
                logger.exception(
                    "Error retrieving analysis json from the catalog service"
                )
                raise

        elif split_url[0].startswith("http"):
            retry = 3
            while retry > 0:
                try:
                    data_response = requests.get(url=url)
                    content = data_response.json()
                    return content
                except requests.HTTPError as ex:
                    logger.exception("HTTP exception: {}. Retrying".format(ex))
                    retry = retry - 1
                    time.sleep(retry * 3)  # Backoff and retry
                except:
                    logger.exception("Non HTTP exception. Retrying")
                    retry = retry - 1

        else:
            raise Exception("Cannot get content from url: {}".format(url))

    def _get_file(self, path):
        with open(path) as r:
            return json.load(r)
