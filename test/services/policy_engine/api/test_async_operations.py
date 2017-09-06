# coding: utf-8

from __future__ import absolute_import

from anchore_engine.services.policy_engine.api.models.update_event import UpdateEvent
from anchore_engine.services.policy_engine.api.models.feed_update_notification import FeedUpdateNotification
from test.services.policy_engine.api import BaseTestCase
from six import BytesIO
from flask import json


class TestDefaultController(BaseTestCase):
    """ DefaultController integration test stubs """

    def test_process_event(self):
        """
        Test case for create_bundle_update

        
        """
        event = UpdateEvent()
        event.event_type = 'image_load'
        event.event_content = {}
        response = self.client.open('/v1/events',
                                    method='POST',
                                    data=json.dumps(event),
                                    content_type='application/json')
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

if __name__ == '__main__':
    import unittest
    unittest.main()
