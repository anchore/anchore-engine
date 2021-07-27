"""
Holds event definitions to be used by services for generating events
"""

from .base import EventBase
from .types import (
    ActivePolicyBundleContentChanged,
    ActivePolicyBundleIdChanged,
    FeedGroupSyncCompleted,
    FeedGroupSyncFailed,
    FeedGroupSyncStarted,
    FeedSyncCompleted,
    FeedSyncFailed,
    FeedSyncStarted,
    FeedSyncTaskCompleted,
    FeedSyncTaskFailed,
    FeedSyncTaskStarted,
    ImageAnalysisFailed,
    ImageAnalysisSuccess,
    ImageArchived,
    ImageArchiveDeleted,
    ImageArchiveDeleteFailed,
    ImageArchivingFailed,
    ImageRegistryLookupFailed,
    ImageRestored,
    ImageRestoreFailed,
    ListTagsFailed,
    PolicyEngineLoadAnalysisFailed,
    RandomWisdomEvent,
    SaveAnalysisFailed,
    ServiceAuthzPluginHealthCheckFailed,
    ServiceDowned,
    ServiceOrphaned,
    ServiceRemoved,
    TagManifestParseFailed,
    TagPolicyEvaluationUpdated,
    TagVulnerabilityUpdated,
    UserAnalyzeImageCompleted,
    UserAnalyzeImageFailed,
)

## TODO: Update refs in __init__ to types.py and fix code instances for invocation of events. Then, add API call.
