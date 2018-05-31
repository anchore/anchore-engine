from anchore_engine.subsys.events import Event

_tag_resource_type = 'tag'


class TagManifestParseFail(Event):
    __event_type__ = 'tag_manifest_parse_fail'
    __resource_type__ = _tag_resource_type

    def __init__(self, user_id, tag, error=None):
        super(TagManifestParseFail, self).__init__(user_id=user_id, level='ERROR', message='Failed to parse image manifest for tag', resource_id=tag, details=error)
