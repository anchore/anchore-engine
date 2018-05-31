import datetime
import json

from anchore_engine.subsys.servicestatus import get_my_service_record


class Event(object):
    __event_type__ = None
    __resource_type__ = None

    def __init__(self, user_id, level, message, details, request_id=None, resource_id=None):
        self.user_id = user_id
        self.level = level
        self.message = message
        self.details = details if isinstance(details, dict) else ({'msg': str(details)} if details is not None else {})
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.request_id = request_id
        self.resource_id = resource_id
        self.service_record = get_my_service_record()

    def to_json(self):
        return json.dumps(self.to_dict())

    def to_dict(self):
        event_dict = dict()
        event_dict['type'] = self.__event_type__
        event_dict['level'] = self.level
        event_dict['message'] = self.message
        event_dict['details'] = self.details
        event_dict['timestamp'] = self.timestamp
        event_dict['resource'] = {'user_id': self.user_id, 'type': self.__resource_type__, 'id': self.resource_id}
        event_dict['source'] = {'request_id': self.request_id}
        if self.service_record:
            event_dict['source']['servicename'] = self.service_record.get('servicename', None)
            event_dict['source']['hostid'] = self.service_record.get('hostid', None)
            event_dict['source']['base_url'] = self.service_record.get('base_url', None)

        return event_dict

    def describe(self):
        return 'event: {}, resource type: {}'.format(self.__event_type__, self.__resource_type__)
