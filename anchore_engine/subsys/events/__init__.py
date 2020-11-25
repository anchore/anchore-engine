"""
Holds event definitions to be used by services for generating events
"""

from .base import EventBase
from .types import FeedSyncTaskStarted
from .types import FeedSyncTaskCompleted
from .types import FeedSyncTaskFailed
from .types import ImageRegistryLookupFailed
from .types import TagVulnerabilityUpdated
from .types import TagPolicyEvaluationUpdated
from .types import ImageAnalysisSuccess
from .types import UserAnalyzeImageFailed
from .types import UserAnalyzeImageCompleted
from .types import ImageAnalysisFailed
from .types import SaveAnalysisFailed
from .types import PolicyEngineLoadAnalysisFailed
from .types import ImageArchived
from .types import ImageArchiveDeleted
from .types import ImageRestored
from .types import ImageRestoreFailed
from .types import ImageArchiveDeleteFailed
from .types import ImageArchivingFailed
from .types import ListTagsFailed
from .types import TagManifestParseFailed
from .types import ActivePolicyBundleIdChanged
from .types import ActivePolicyBundleContentChanged
from .types import ServiceOrphaned
from .types import ServiceDowned
from .types import ServiceRemoved
from .types import ServiceAuthzPluginHealthCheckFailed
from .types import RandomWisdomEvent
from .types import FeedGroupSyncCompleted
from .types import FeedGroupSyncFailed
from .types import FeedGroupSyncStarted
from .types import FeedSyncCompleted
from .types import FeedSyncFailed
from .types import FeedSyncStarted


## TODO: Update refs in __init__ to types.py and fix code instances for invocation of events. Then, add API call.
