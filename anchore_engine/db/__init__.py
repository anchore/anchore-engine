from .entities.catalog import (
    Anchore,
    ArchivedImage,
    ArchivedImageDocker,
    ArchiveTransitionHistoryEntry,
    ArchiveTransitionRule,
    ArchiveTransitions,
    CatalogImage,
    CatalogImageDocker,
    Event,
    ImageImportContent,
    ImageImportOperation,
    Lease,
    LegacyArchiveDocument,
    ObjectStorageMetadata,
    ObjectStorageRecord,
    PolicyBundle,
    PolicyEval,
    Queue,
    QueueItem,
    QueueMeta,
    Registry,
    Service,
    Subscription,
    TransitionHistoryState,
    User,
)
from .entities.common import (
    end_session,
    get_session,
    get_thread_scoped_session,
    initialize,
    session_scope,
)

# Identity types
from .entities.identity import (
    AccessCredential,
    Account,
    AccountStates,
    AccountTypes,
    AccountUser,
    UserAccessCredentialTypes,
    UserTypes,
)

# Policy engine types
from .entities.policy_engine import (
    AnalysisArtifact,
    CachedPolicyEvaluation,
    CpeV2Vulnerability,
    CpeVulnerability,
    DistroMapping,
    DistroNamespace,
    FeedGroupMetadata,
    FeedMetadata,
    FilesystemAnalysis,
    FixedArtifact,
    GemMetadata,
    GenericFeedDataRecord,
    GrypeDBFeedMetadata,
    Image,
    ImageCpe,
    ImageGem,
    ImageNpm,
    ImagePackage,
    ImagePackageManifestEntry,
    ImagePackageVulnerability,
    ImageVulnerabilitiesReport,
    NpmMetadata,
    NvdMetadata,
    NvdV2Metadata,
    VulnDBCpe,
    VulnDBMetadata,
    Vulnerability,
    VulnerableArtifact,
    select_nvd_classes,
)

# Task types
from .entities.tasks import ArchiveMigrationTask, Task


def Session():
    return get_session()
