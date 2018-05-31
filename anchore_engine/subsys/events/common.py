import datetime
import json

from anchore_engine.subsys.servicestatus import get_my_service_record


class Event(object):
    __type__ = None

    def __init__(self, user_id, level, message, details, resource_type, request_id=None, resource_id=None):
        self.user_id = user_id
        self.level = level
        self.message = message
        self.details = details if details else {}
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.request_id = request_id
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.service_record = get_my_service_record()

    def to_json(self):
        msg = dict()
        msg['type'] = self.__type__
        msg['level'] = self.level
        msg['message'] = self.message
        msg['details'] = self.details
        msg['timestamp'] = self.timestamp
        msg['resource'] = {'user_id': self.user_id, 'type': self.resource_type, 'id': self.resource_id}
        msg['source'] = {'request_id': self.request_id}
        if self.service_record:
            msg['source']['servicename'] = self.service_record.get('servicename', None)
            msg['source']['hostid'] = self.service_record.get('hostid', None)
            msg['source']['base_url'] = self.service_record.get('base_url', None)

        return json.dumps(msg)
