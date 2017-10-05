from __future__ import absolute_import

import time
import logging
import docker_registry_client._BaseClient
from requests import get


logging.basicConfig(level='DEBUG', format='%(asctime)-15s %(levelname)s %(filename)s %(message)s')
logger = logging.getLogger(__name__)

class TestAuthCommonBaseClient(object):
    """
    Runs tests of the auth handling against DockerHub. Requires network connectivity but no DockerHub credentials
    """
    host = 'https://index.docker.io'
    version_check_url = '/v2/'
    nginx_url = '/v2/library/nginx/tags/list'
    nginx_latest_manifest = '/v2/library/nginx/manifests/latest'

    def test_check_status(self):
        logger.info('Testing Listing the catalog')
        response = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)._http_call(self.version_check_url, method=get)
        logger.info('Got response: %s' % str(response))

    def test_tag_listing(self):
        logger.info('Testing Tag listing')
        response = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)._http_call(self.nginx_url,
                                                                                     method=get)
        logger.info('Got response: %s' % str(response))
        if hasattr(response, 'content'):
            logger.info('Content: ' + str(response.content))

    def test_token_timeout(self):
        logger.info('Testing token timeouts')
        client = docker_registry_client._BaseClient.AuthCommonBaseClient(self.host)
        try:

            for i in range(0, 5):
                response =client._http_call(self.nginx_latest_manifest, method=get)
                logger.info(str(response))
                response = None
                logger.info('Sleeping for 5 + 1 sec minutes to try again')
                time.sleep((5*60) + 1)
        except Exception as e:
            logger.error('Exception: ' + e.message, exc_info=1)
            raise e

    def test_token_invalidate(self):
        logger.info('Testing token invalidation')
        t = docker_registry_client._BaseClient.OAuth2TokenHandler()
        t._add_token('/', 'http://testurl', {'param':'value'}, {'token':'abc'})
        t.invalidate_token('abc')
        try:
            t.lookup_by_path('/')
            logger.info('Expected a KeyError')
            raise Exception('Failed test, did not invalidate token properly')
        except KeyError:
            return

if __name__ == '__main__':
    t = TestAuthCommonBaseClient()
    logger.info('Checking status')
    t.test_check_status()
    logger.info('Listing nginx tags')
    t.test_tag_listing()
    logger.info('Testing token invalidation')
    t.test_token_invalidate()
    logger.info('Testing timeout')
    t.test_token_timeout()



