import unittest
import os
import datetime
from anchore_engine.clients.feeds.feed_service import get_client, InvalidCredentialsError


class TestAnchoreIOFeedClient(unittest.TestCase):
    registered_user_name = os.environ.get('ANCHORE_ENGINE_FEED_USER')
    registered_user_passwd = os.environ.get('ANCHORE_ENGINE_FEED_PASS')
    feed_url = 'https://ancho.re/v1/service/feeds'
    client_url = 'https://ancho.re/v1/account/users'
    token_url = 'https://ancho.re/oauth/token'

    def test_anon_user(self):
        test_client = get_client(feeds_url=self.feed_url,
                                 token_url=self.token_url,
                                 client_url=self.client_url,
                                 user=('anon@ancho.re', 'pbiU2RYZ2XrmYQ'),
                                 conn_timeout=3,
                                 read_timeout=10)
        for f in test_client.list_feeds().feeds:
            try:
                test_client.list_feed_groups(f.name)
            except Exception as e:
                print(('Caught: {} for feed:  {}'.format(e, f)))
        test_client.get_feed_group_data('vulnerabilities', 'debian:8',since=datetime.datetime.utcnow())

    def test_registered_user(self):
        test_client = get_client(feeds_url=self.feed_url,
                                 token_url=self.token_url,
                                 client_url=self.client_url,
                                 user=(self.registered_user_name, self.registered_user_passwd),
                                 conn_timeout=3,
                                 read_timeout=10)

        for f in test_client.list_feeds().feeds:
            try:
                groups = test_client.list_feed_groups(f.name)
                for g in groups.groups:
                    print(('Feed {} Group {}'.format(f.name, g.name)))
            except Exception as e:
                print(('Caught: {} for feed:  {}'.format(e, f)))


    def test_auth_error(self):
        with self.assertRaises(InvalidCredentialsError) as e:
            test_client = get_client(feeds_url=self.feed_url,
                                     token_url=self.token_url,
                                     client_url=self.client_url,
                                     user=('anon@ancho.re', 'foobar'),
                                     conn_timeout=3,
                                     read_timeout=10)
            f = test_client.list_feeds()

    def test_feed_sync(self):
        test_client = get_client(feeds_url=self.feed_url,
                                 token_url=self.token_url,
                                 client_url=self.client_url,
                                 user=('anon@ancho.re', 'pbiU2RYZ2XrmYQ'),
                                 conn_timeout=3,
                                 read_timeout=10)
        for f in test_client.list_feeds().feeds:
            try:
                test_client.list_feed_groups(f.name)
            except Exception as e:
                print(('Caught: {} for feed:  {}'.format(e, f)))


        next_token = False
        since_time = datetime.datetime.utcnow() - datetime.timedelta(days=2)
        since_time = None
        while next_token is not None:
            print('Getting a page of data')
            if next_token:
                last_token = next_token
                print(('Using token: {}'.format(next_token)))
                data = test_client.get_feed_group_data('vulnerabilities', 'debian:8', since=since_time, next_token=next_token)
                next_token = data.next_token
                print(('Got {} items and new next token: {}'.format(len(data.data), next_token)))
            else:
                last_token = None
                data = test_client.get_feed_group_data('vulnerabilities', 'debian:8', since=since_time)
                next_token = data.next_token
                print(('Got {} items and new next token: {}'.format(len(data.data), next_token)))

            if next_token:
                self.assertNotEqual(next_token, last_token)
            self.assertGreater(len(data.data), 0)



