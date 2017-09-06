# coding: utf-8

from __future__ import absolute_import
import datetime

from kirk.api.models.image_update_notification import ImageUpdateNotification
from kirk.api.models.feed_update_notification import FeedUpdateNotification
from kirk.api.models.vulnerability_listing import VulnerabilityListing
from kirk.api.models.image_ingress_request import ImageIngressRequest
from kirk.api.models.image_ingress_response import ImageIngressResponse
from tests.api import BaseTestCase
from tests import LocalTestDataEnvironment
from flask import json


class TestSynchronousController(BaseTestCase):
    """ DefaultController integration test stubs """
    test_env = LocalTestDataEnvironment('/Users/zhill/local_kirk_testing')


    def test_list_image_users(self):
        """
        Test case for list_image_users

        List user ids known to the eval system
        """
        response = self.client.open('/v1/users',
                                    method='GET',
                                    query_string=[])
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_list_user_images(self):
        """
        Test case for list_user_images

        List the image ids for the specified user
        """
        response = self.client.open('/v1/users/{user_id}/images'.format(user_id='user_id_example'),
                                    method='GET',
                                    query_string=[])
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_image_check_inline(self):
        """
        Test case for check_image
        :return:
        """


        test_bundle = self.test_env.get_bundle('default')

        response = self.client.open('/v1/users/{user_id}/images/check_inline'.format(user_id='user_id_example'),
                                    method='GET',
                                    query_string=[],
                                    data=json.dumps(test_bundle))
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_create_feed_update(self):
        """
        Test case for create_feed_update


        """
        notification = FeedUpdateNotification()
        notification.event_timestamp = datetime.datetime.utcnow()
        notification.feed_name = 'vulnerabilities'
        notification.feed_group = 'ubuntu:12.04'

        response = self.client.open('/v1/notifications/feeds',
                                    method='POST',
                                    data=json.dumps(notification.to_dict()).encode('utf-8'),
                                    content_type='application/json')
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_create_image_update(self):
        """
        Test case for create_image_update


        """
        notification = ImageUpdateNotification()
        response = self.client.open('/v1/notifications/images',
                                    method='POST',
                                    data=json.dumps(notification),
                                    content_type='application/json')
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_list_user_images(self):

        response = self.client.open('/v1/users/0/images',
                         method='GET',
                         content_type='application/json')
        self.assert200(response, 'Response body is : ' + response.data.decode('utf-8'))

    def test_list_image_users(self):
        """
        Test case for list_image_users

        List user ids known to the eval system
        """
        query_string = [('page', 56)]
        response = self.client.open('/v1/users',
                                    method='GET',
                                    query_string=query_string)
        self.assert200(response, "Response body is : " + response.data.decode('utf-8'))

    def test_get_vulnerabilities(self):
        response = self.client.open('/v1/users/0/images/abc/vulnerabilities',
                                    method='GET',
                                    query_string='')
        self.assert200(response, 'Response body is : ' + response.data.decode('utf-8'))

    def test_policy_eval(self):
        pass


if __name__ == '__main__':
    import unittest
    unittest.main()
