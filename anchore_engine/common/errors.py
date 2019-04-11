import enum

class AnchoreError(enum.Enum):
    REGISTRY_PERMISSION_DENIED = "The registry has reported permission denied for the requested registry resource"
    REGISTRY_IMAGE_NOT_FOUND = "The requested image (tag, digest) cannot be found in the requested registry"
    SKOPEO_UNKNOWN_ERROR = "The skopeo command has failed due to an error that is not explicitly handled, see the command output/error for more information"
    UNKNOWN = "An unknown error has occurred, please consult the anchore service logs for more information"
