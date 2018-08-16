"""
Exceptions for the engine
"""


class EngineException(Exception):
    pass

class ImageLoadError(EngineException):
    pass


class NoAnalysisFoundError(EngineException):
    pass


class InvalidImageStateError(EngineException):
    pass


class FeedGroupSyncError(EngineException):
    pass


class FeedNotFoundError(EngineException):
    pass


class VulnerabilityDataUnavailableError(EngineException):
    pass

