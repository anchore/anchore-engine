"""
Holds event definitions to be used by services for generating events
"""

from .common import Event
from .feeds import FeedSyncStart
from .feeds import FeedSyncComplete
from .feeds import FeedSyncFail
from .images import ImageVulnerabilityUpdate
from .images import ImagePolicyEvalUpdate
from .images import AnalyzeImageSuccess
from .images import AnalyzeImageFail
from .images import ArchiveAnalysisFail
from .images import LoadAnalysisFail
from .images import ImageArchived
from .images import ImageArchiveDeleted
from .images import ImageRestored
from .images import ImageRestoreFailed
from .images import ImageArchiveDeleteFailed
from .images import ImageArchivingFailed
from .repositories import ListTagsFail
from .tags import TagManifestParseFail
from .policies import PolicyBundleSyncFail
from .services import ServiceOrphanedEvent
from .services import ServiceDownEvent
from .services import ServiceRemovedEvent
from .services import ServiceAuthzPluginHealthCheckFail
