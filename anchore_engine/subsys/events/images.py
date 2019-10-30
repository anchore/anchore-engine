from anchore_engine.subsys.events import Event

_image_digest_resource_type = 'image_digest'
_image_tag_resource_type = 'image_tag'

class ImageVulnerabilityUpdate(Event):
    __event_type__ = 'image_vuln_update'
    __resource_type__ = _image_tag_resource_type

    def __init__(self, user_id, full_tag, data={}):
        super(ImageVulnerabilityUpdate, self).__init__(user_id=user_id, level='INFO', message='Vulnerability update detected for image', resource_id=full_tag, details=data)


class ImagePolicyEvalUpdate(Event):
    __event_type__ = 'image_policy_eval_update'
    __resource_type__ = _image_tag_resource_type

    def __init__(self, user_id, full_tag, data={}):
        super(ImagePolicyEvalUpdate, self).__init__(user_id=user_id, level='INFO', message='Policy evaluation update detected for image', resource_id=full_tag, details=data)


class AnalyzeImageSuccess(Event):
    __event_type__ = 'analyze_image_success'
    __resource_type__ = _image_tag_resource_type

    def __init__(self, user_id, full_tag, data={}):
        super(AnalyzeImageSuccess, self).__init__(user_id=user_id, level='INFO', message='Image successfully analyzed', resource_id=full_tag, details=data)
    

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


class ImageArchived(Event):
    __event_type__ = 'image_analysis_archived'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, task_id=None):
        super().__init__(user_id=user_id, level='INFO', message='Analyzed image added to archive', resource_id=image_digest, details='Archived by task {}'.format(task_id) if task_id else 'Archived by API request')


class ImageArchivingFailed(Event):
    __event_type__ = 'image_analysis_archiving_failed'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, task_id=None, err=None):
        super().__init__(user_id=user_id, level='ERROR', message='Analyzed image migration to archive failed', resource_id=image_digest, details='Archiving failed due to {} {}'.format(err, 'in task {}'.format(task_id if task_id else 'by API request')))


class ImageRestored(Event):
    __event_type__ = 'archived_image_restored'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest):
        super().__init__(user_id=user_id, level='INFO', message='Archived image restored to active images', resource_id=image_digest, details='Restored by API request')


class ImageRestoreFailed(Event):
    __event_type__ = 'archived_image_restore_failed'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, err=None):
        super().__init__(user_id=user_id, level='ERROR', message='Archived image restore to active images failed', resource_id=image_digest, details='Restore failed due to {}'.format(err))


class ImageArchiveDeleted(Event):
    __event_type__ = 'archived_image_deleted'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, task_id=None):
        super().__init__(user_id=user_id, level='INFO', message='Archived image analysis deleted', resource_id=image_digest, details='Deleted by task {}'.format(task_id if task_id else 'Archived by API request'))


class ImageArchiveDeleteFailed(Event):
    __event_type__ = 'archived_image_delete_failed'
    __resource_type__ = _image_digest_resource_type

    def __init__(self, user_id, image_digest, task_id=None, err=None):
        super().__init__(user_id=user_id, level='ERROR', message='Archived image analysis deletion failed', resource_id=image_digest, details='Deletion by {} failed due to: {}'.format('task {}'.format(task_id if task_id else 'API request'), err))
