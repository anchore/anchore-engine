from .common import Event

_repo_resource_type = 'repository'


class ListTagsFail(Event):
    __event_type__ = 'list_tags_fail'
    __resource_type__ = _repo_resource_type

    def __init__(self, user_id, registry, repository, error=None):
        super(ListTagsFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to list tags in repository', resource_id='/'.join([registry, repository]), details=error)
