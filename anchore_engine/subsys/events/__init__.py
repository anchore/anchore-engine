"""
Holds event definitions to be used by services for generating events
"""

from .common import Event
from .feeds import FeedSyncStart
from .feeds import FeedSyncComplete
from .feeds import FeedSyncFail
from .images import AnalyzeImageFail
from .images import ArchiveAnalysisFail
from .images import LoadAnalysisFail
from .repositories import ListTagsFail
from .tags import TagManifestParseFail
from .policies import PolicyBundleSyncFail
from .services import ServiceOrphanedEvent
from .services import ServiceAuthzPluginHealthCheckFail
