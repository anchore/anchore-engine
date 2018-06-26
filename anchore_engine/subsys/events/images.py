from anchore_engine.subsys.events import Event

_image_digest_resource_type = 'image_digest'


class AnalyzeImageFail(Event):
    __event_type__ = 'analyze_image_fail'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, error=None):
        super(AnalyzeImageFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to analyze image', resource_id=image_digest, details=error)


class ArchiveAnalysisFail(Event):
    __event_type__ = 'archive_analysis_fail'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, error=None):
        super(ArchiveAnalysisFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to archive image analysis data', resource_id=image_digest, details=error)


class LoadAnalysisFail(Event):
    __event_type__ = 'load_analysis_fail'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, error=None):
        super(LoadAnalysisFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to load image analysis to policy engine', resource_id=image_digest, details=error)
