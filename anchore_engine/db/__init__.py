from .entities.common import session_scope
from .entities.common import initialize
from .entities.common import get_thread_scoped_session
from .entities.common import end_session, get_session

from .entities.catalog import Anchore
from .entities.catalog import ArchiveDocument
from .entities.catalog import CatalogImage
from .entities.catalog import CatalogImageDocker
from .entities.catalog import Event
from .entities.catalog import PolicyBundle
from .entities.catalog import PolicyEval
from .entities.catalog import QueueItem
from .entities.catalog import Queue
from .entities.catalog import QueueMeta
from .entities.catalog import Registry
from .entities.catalog import Service
from .entities.catalog import Subscription
from .entities.catalog import User
from .entities.catalog import Lease
from .entities.catalog import ArchiveMetadata
from .entities.catalog import ObjectStorageRecord

# Identity types
from .entities.identity import AccountTypes
from .entities.identity import AccountStates
from .entities.identity import Account
from .entities.identity import AccountUser
from .entities.identity import UserAccessCredentialTypes
from .entities.identity import AccessCredential

# Task types
from .entities.tasks import Task, ArchiveMigrationTask

# Policy engine types
from .entities.policy_engine import Image
from .entities.policy_engine import ImagePackage
from .entities.policy_engine import ImageGem
from .entities.policy_engine import ImageNpm
from .entities.policy_engine import ImageCpe
from .entities.policy_engine import ImagePackageVulnerability
from .entities.policy_engine import FeedMetadata
from .entities.policy_engine import FeedGroupMetadata
from .entities.policy_engine import GenericFeedDataRecord
from .entities.policy_engine import Vulnerability
from .entities.policy_engine import VulnerableArtifact
from .entities.policy_engine import FixedArtifact
from .entities.policy_engine import DistroMapping
from .entities.policy_engine import DistroNamespace
from .entities.policy_engine import FilesystemAnalysis
from .entities.policy_engine import NpmMetadata
from .entities.policy_engine import GemMetadata
from .entities.policy_engine import NvdMetadata
from .entities.policy_engine import CpeVulnerability
from .entities.policy_engine import AnalysisArtifact
from .entities.policy_engine import ImagePackageManifestEntry
from .entities.policy_engine import CachedPolicyEvaluation

def Session():
    return get_session()
