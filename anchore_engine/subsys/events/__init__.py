"""
Holds event definitions to be used by services for generating events
"""

from .base import EventBase
from .types import FeedSyncStarted
from .types import FeedSyncCompleted
from .types import FeedSyncFailed
from .types import ImageRegistryLookupFailed
from .types import TagVulnerabilityUpdated
from .types import TagPolicyEvaluationUpdated
from .types import AnalyzeImageSuccess
from .types import UserAnalyzeImageFailed
from .types import ImageAnalysisFail
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


## TODO: Update refs in __init__ to types.py and fix code instances for invocation of events. Then, add API call.