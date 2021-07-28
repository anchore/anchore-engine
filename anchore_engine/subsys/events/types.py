import random

from .base import EventLevel, EventBase, CategoryDescriptor

_image_digest_resource_type = "image_digest"
_image_tag_resource_type = "image_tag"
_image_reference_type = (
    "image_reference"  # Input is a valid image reference, may be tag or digest
)
_repo_resource_type = "repository"
_feeds_resource_type = "feeds"
_feed_resource_type = "feed"
_feed_group_resource_type = "feed_group"


class SystemCategory(EventBase):
    """
    Parent class for events in the system category
    """

    __category__ = CategoryDescriptor(
        name="system",
        description="System events to indicate what is happening in the system. State changes, async processes, etc all generate events in this category.",
    )


class UserCategory(EventBase):
    """
    Parent class for events in the user category
    """

    __category__ = CategoryDescriptor(
        name="user",
        description="User events are specific events of interest to a user and intended for human consumption as well as automation",
    )


class UserImageSubcategory(UserCategory):
    __subcategory__ = CategoryDescriptor(
        name="image", description="Events from image state/status"
    )


class UserCheckSubcategory(UserCategory):
    __subcategory__ = CategoryDescriptor(
        name="checks", description="Events from checks/policy evaluations on resources"
    )


class TagVulnerabilityUpdated(UserCheckSubcategory):
    __event_type__ = "tag.vulnerabilities.update"
    __resource_type__ = _image_tag_resource_type
    __level__ = EventLevel.INFO
    __message__ = "Vulnerability update detected for tagged image"

    def __init__(self, user_id, full_tag, data=None):
        super(TagVulnerabilityUpdated, self).__init__(
            user_id=user_id, resource_id=full_tag, details=data
        )


class TagPolicyEvaluationUpdated(UserCheckSubcategory):
    __event_type__ = "tag.policy_evaluation.update"
    __resource_type__ = _image_tag_resource_type
    __level__ = EventLevel.INFO
    __message__ = "Policy evaluation update detected for a tagged image"

    def __init__(self, user_id, full_tag, data=None):
        super(TagPolicyEvaluationUpdated, self).__init__(
            user_id=user_id, resource_id=full_tag, details=data
        )


class UserAnalyzeImageFailed(UserImageSubcategory):
    __event_type__ = "analysis.failed"
    __message__ = "Failed to analyze image"
    __resource_type__ = _image_tag_resource_type
    __level__ = EventLevel.ERROR

    def __init__(self, user_id, full_tag, error=None):
        super().__init__(user_id=user_id, resource_id=full_tag, details=error)


class UserAnalyzeImageCompleted(UserImageSubcategory):
    __event_type__ = "analysis.completed"
    __message__ = "Image analysis available"
    __resource_type__ = _image_tag_resource_type

    def __init__(self, user_id, full_tag, data=None):
        super().__init__(user_id=user_id, resource_id=full_tag, details=data)


class SystemImageAnalysisSubcategory(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="image_analysis",
        description="Events from the image analysis/import process",
    )
    __resource_type__ = _image_digest_resource_type


class AnalysisArchiveSubcategory(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="analysis_archive",
        description="Events from the image analysis archiving process",
    )
    __resource_type__ = _image_digest_resource_type


class ImageRegistryLookupFailed(SystemImageAnalysisSubcategory):
    __event_type__ = "registry_lookup_failed"
    __resource_type__ = _image_reference_type
    __level__ = EventLevel.ERROR
    __message__ = "Referenced image not found in registry"

    def __init__(self, user_id, image_pull_string, data=None):
        super().__init__(user_id=user_id, resource_id=image_pull_string, details=data)


class ImageAnalysisError(SystemImageAnalysisSubcategory):
    __level__ = EventLevel.ERROR


class ImageAnalysisFailed(ImageAnalysisError):
    __event_type__ = "failed"
    __message__ = "Failed to analyze image"

    def __init__(self, user_id, image_digest, error=None):
        super().__init__(user_id=user_id, resource_id=image_digest, details=error)


class ImageAnalysisSuccess(SystemImageAnalysisSubcategory):
    __event_type__ = "completed"
    __resource_type__ = _image_tag_resource_type
    __level__ = EventLevel.INFO
    __message__ = "Image successfully analyzed"

    def __init__(self, user_id, full_tag, data=None):
        super(ImageAnalysisSuccess, self).__init__(
            user_id=user_id, resource_id=full_tag, details=data
        )


class SaveAnalysisFailed(ImageAnalysisError):
    __event_type__ = "catalog_save_failed"
    __level__ = EventLevel.ERROR
    __message__ = "Failed to load image analysis from analyzer to catalog"

    def __init__(self, user_id, image_digest, error=None):
        super().__init__(user_id=user_id, resource_id=image_digest, details=error)


class PolicyEngineLoadAnalysisFailed(ImageAnalysisError):
    __event_type__ = "policy_engine_load_failed"
    __message__ = "Failed to load image analysis from analyzer to policy engine"

    def __init__(self, user_id, image_digest, error=None):
        super().__init__(user_id=user_id, resource_id=image_digest, details=error)


class ImageArchived(AnalysisArchiveSubcategory):
    __event_type__ = "image_archived"
    __message__ = "Analyzed image added to archive"

    def __init__(self, user_id, image_digest, task_id=None):
        super().__init__(
            user_id=user_id,
            resource_id=image_digest,
            details="Archived by task {}".format(task_id)
            if task_id
            else "Archived by API request",
        )


class ImageArchivingFailed(AnalysisArchiveSubcategory):
    __event_type__ = "image_archive_failed"
    __level__ = EventLevel.ERROR
    __message__ = "Analyzed image migration to archive failed"

    def __init__(self, user_id, image_digest, task_id=None, err=None):
        super().__init__(
            user_id=user_id,
            resource_id=image_digest,
            details="Archiving failed due to {} {}".format(
                err, "in task {}".format(task_id if task_id else "by API request")
            ),
        )


class ImageRestored(SystemImageAnalysisSubcategory):
    __event_type__ = "restored_from_archive"
    __message__ = "Archived image restored to active images"

    def __init__(self, user_id, image_digest):
        super().__init__(
            user_id=user_id, resource_id=image_digest, details="Restored by API request"
        )


class ImageRestoreFailed(ImageAnalysisError):
    __event_type__ = "restore_from_archive_failed"
    __message__ = "Archived image restore to active images failed"

    def __init__(self, user_id, image_digest, err=None):
        super().__init__(
            user_id=user_id,
            resource_id=image_digest,
            details="Restore failed due to {}".format(err),
        )


class ImageArchiveDeleted(AnalysisArchiveSubcategory):
    __event_type__ = "archived_image_deleted"
    __message__ = "Archived image analysis deleted"

    def __init__(self, user_id, image_digest, task_id=None):
        super().__init__(
            user_id=user_id,
            resource_id=image_digest,
            details="Deleted by task {}".format(
                task_id if task_id else "Archived by API request"
            ),
        )


class ImageArchiveDeleteFailed(AnalysisArchiveSubcategory):
    __event_type__ = "archived_image_delete_failed"
    __level__ = EventLevel.ERROR
    __message__ = "Archived image analysis deletion failed"

    def __init__(self, user_id, image_digest, task_id=None, err=None):
        super().__init__(
            user_id=user_id,
            resource_id=image_digest,
            details="Deletion by {} failed due to: {}".format(
                "task {}".format(task_id if task_id else "API request"), err
            ),
        )


class TagManifestParseFailed(SystemImageAnalysisSubcategory):
    __event_type__ = "manifest_parse_fail"
    __resource_type__ = _image_tag_resource_type
    __level__ = EventLevel.ERROR
    __message__ = "Failed to parse image manifest for tag"

    def __init__(self, user_id, tag, error=None):
        super().__init__(user_id=user_id, resource_id=tag, details=error)


class SystemRepositorySubcategory(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="repository", description="Events related to repository-watch operations"
    )


class ListTagsFailed(SystemRepositorySubcategory):
    __event_type__ = "list_tags_fail"
    __resource_type__ = _repo_resource_type
    __level__ = EventLevel.ERROR
    __message__ = "Failed to list tags in repository"

    def __init__(self, user_id, registry, repository, error=None):
        super(ListTagsFailed, self).__init__(
            user_id=user_id, resource_id="/".join([registry, repository]), details=error
        )


class SystemFeedsSubcategory(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="feeds", description="Events from data feed operations"
    )


class FeedSyncTaskStarted(SystemFeedsSubcategory):
    __event_type__ = "sync.started"
    __resource_type__ = _feeds_resource_type
    __message__ = "Feeds sync task started"

    def __init__(self, groups):
        super().__init__(user_id="admin", details={"sync_feed_types": groups})


class FeedSyncTaskCompleted(SystemFeedsSubcategory):
    __event_type__ = "sync.completed"
    __resource_type__ = _feeds_resource_type
    __message__ = "Feeds sync task completed"

    def __init__(self, groups):
        super().__init__(user_id="admin", details={"sync_feed_types": groups})


class FeedSyncTaskFailed(SystemFeedsSubcategory):
    __event_type__ = "sync.failed"
    __resource_type__ = _feeds_resource_type
    __level__ = EventLevel.ERROR
    __message__ = "Feeds sync task failed"

    def __init__(self, groups, error):
        super().__init__(
            user_id="admin", details={"cause": str(error), "sync_feed_types": groups}
        )


class FeedSyncStarted(SystemFeedsSubcategory):
    __event_type__ = "sync.feed_started"
    __resource_type__ = _feed_resource_type
    __message__ = "Feed sync started"

    def __init__(self, feed):
        super().__init__(user_id="admin", resource_id=feed, details=None)


class FeedSyncCompleted(SystemFeedsSubcategory):
    __event_type__ = "sync.feed_completed"
    __resource_type__ = _feed_resource_type
    __message__ = "Feed sync completed"

    def __init__(self, feed):
        super().__init__(user_id="admin", resource_id=feed, details=None)


class FeedSyncFailed(SystemFeedsSubcategory):
    __event_type__ = "sync.feed_failed"
    __resource_type__ = _feed_resource_type
    __level__ = EventLevel.ERROR
    __message__ = "Feed sync failed"

    def __init__(self, feed, error):
        super().__init__(
            user_id="admin", resource_id=feed, details={"cause": str(error)}
        )


class FeedGroupSyncStarted(SystemFeedsSubcategory):
    __event_type__ = "sync.group_started"
    __resource_type__ = _feed_group_resource_type
    __message__ = "Feed group sync started"

    def __init__(self, feed, group):
        super().__init__(user_id="admin", resource_id=feed + "/" + group, details=None)


class FeedGroupSyncCompleted(SystemFeedsSubcategory):
    __event_type__ = "sync.group_completed"
    __resource_type__ = _feed_group_resource_type
    __message__ = "Feed group sync completed"

    def __init__(self, feed, group, result=None):
        super().__init__(
            user_id="admin", resource_id=feed + "/" + group, details={"result": result}
        )


class FeedGroupSyncFailed(SystemFeedsSubcategory):
    __event_type__ = "sync.group_failed"
    __resource_type__ = _feed_group_resource_type
    __level__ = EventLevel.ERROR
    __message__ = "Feed group sync failed"

    def __init__(self, feed, group, error):
        super().__init__(
            user_id="admin",
            resource_id=feed + "/" + group,
            details={"cause": str(error)},
        )


class UserPolicySubcategory(UserCategory):
    __subcategory__ = CategoryDescriptor(
        name="policy", description="Events from policy content or configuration changes"
    )
    __resource_type__ = "policy_bundle"
    __level__ = EventLevel.INFO


# policy user category events


class ActivePolicyBundleIdChanged(UserPolicySubcategory):
    __event_type__ = "active.updated"
    __message__ = "Active policy bundle updated to a different bundle"

    def __init__(self, user_id, data=None):
        super().__init__(user_id=user_id, details=data)


class ActivePolicyBundleContentChanged(UserPolicySubcategory):
    __event_type__ = "active.content_change"
    __message__ = "Active policy bundle content changed"

    def __init__(self, user_id, data=None):
        super().__init__(user_id=user_id, details=data)


class SystemServiceSubcategory(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="service", description="Events from service state transitions"
    )
    __resource_type__ = "service"
    __level__ = EventLevel.ERROR


class ServiceOrphaned(SystemServiceSubcategory):
    __event_type__ = "state_transition.orphaned"
    __message__ = "Service orphaned"

    def __init__(self, user_id, name, host, url, cause):
        super().__init__(
            user_id=user_id,
            resource_id=url,
            details={"service_name": name, "host_id": host, "cause": cause},
        )


class ServiceDowned(SystemServiceSubcategory):
    __event_type__ = "state_transition.down"
    __message__ = "Service down"

    def __init__(self, user_id, name, host, url, cause):
        super().__init__(
            user_id=user_id,
            resource_id=url,
            details={"service_name": name, "host_id": host, "cause": cause},
        )


class ServiceRemoved(SystemServiceSubcategory):
    __event_type__ = "removed"
    __message__ = "Service removed"

    def __init__(self, user_id, name, host, url, cause):
        super().__init__(
            user_id=user_id,
            resource_id=url,
            details={"service_name": name, "host_id": host, "cause": cause},
        )


class ServiceAuthzPluginHealthCheckFailed(SystemServiceSubcategory):
    __event_type__ = "authz_plugin_healthcheck_failed"
    __message__ = "Configured authz plugin failing health check"

    def __init__(self, user_id, name, host, plugin, details):
        """

        :param user_id: User Id reporting
        :param name: str name of the service
        :param host: str host_id of service
        :param plugin: str name of the plugin
        :param details: json dict with
        """
        super().__init__(
            user_id=user_id,
            details={
                "service_name": name,
                "host_id": host,
                "plugin": plugin,
                "cause": details,
            },
        )


class RandomWisdomEvent(SystemCategory):
    __subcategory__ = CategoryDescriptor(
        name="test", description="Test events with randomly generated content"
    )
    __event_type__ = "random_wisdom"
    __message__ = "Unsolicited random wisdom of the moment"
    __resource_type__ = "wisdom"

    _quotes_ = [
        "All bad poetry springs from genuine feeling - Oscar Wilde",
        "The truth is rarely pure and never simple - Oscar Wilde",
        "Moderation is a fatal thing. Nothing succeeds like excess - Oscar Wilde",
        "The true sign of intelligence is not knowledge but imagination - Albert Einstein",
        "Reality is merely an illusion, albeit a very persistent one - Albert Einstein",
        "Peace cannot be kept by force, it can only be achieved by understanding - Albert Einstein",
        "Never give a sword to a man who can't dance - Confucius",
        "It is better to keep your mouth closed and let people think you are a fool than to open it and remove all doubt - Mark Twain",
        "Against the assault of laughter, nothing can stand - Mark Twain",
        "The very ink with which history is written is merely fluid prejudice - Mark Twain",
        "Never pick a fight with people who buy ink by the barrel - Mark Twain",
    ]

    @staticmethod
    def get_random_quote():
        return random.choice(RandomWisdomEvent._quotes_)

    def __init__(self):
        super().__init__(user_id="admin", details=RandomWisdomEvent.get_random_quote())
