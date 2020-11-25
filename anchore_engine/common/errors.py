import enum


class AnchoreError(enum.Enum):
    REGISTRY_PERMISSION_DENIED = "The registry has reported permission denied for the requested registry resource"
    REGISTRY_IMAGE_NOT_FOUND = (
        "The requested image (tag, digest) cannot be found in the requested registry"
    )
    REGISTRY_NOT_ACCESSIBLE = (
        "The registry is not accessible on the network from the anchore engine service"
    )
    REGISTRY_NOT_SUPPORTED = (
        "Anchore cannot access the specified registry as supporting the v2 registry API"
    )
    SKOPEO_UNKNOWN_ERROR = "The skopeo command has failed due to an error that is not explicitly handled, see the command output/error for more information"
    UNKNOWN = "An unknown error has occurred, please consult the anchore service logs for more information"
    FEED_SYNC_ALREADY_IN_PROGRESS = "Feed sync lock held by another process"
    OSARCH_MISMATCH = "The image manifest from the registry does not container an arch/os that matches local environment"
