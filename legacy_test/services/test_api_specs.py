"""
Brings up each api in a test process to ensure spec is clean and works
"""

import unittest
import connexion
from connexion.mock import MockResolver
import os
import signal
import time
import urllib.request, urllib.parse, urllib.error


class TestServiceApiSpecs(unittest.TestCase):
    prefix = os.environ['PWD']
    service_swaggers = [
        'anchore_engine/services/apiext/swagger',
        'anchore_engine/services/catalog/swagger',
        'anchore_engine/services/simplequeue/swagger',
        'anchore_engine/services/analyzer/swagger',
        'anchore_engine/services/policy_engine/swagger',
        'anchore_engine/services/kubernetes_webhook/swagger'
    ]

    def test_api_service(self):
        """
        Creates a mocked interface for each specified swagger spec and runs a server with a forked process to ensure swagger validates fully.

        :return:
        """

        port = 8088
        for swagger in self.service_swaggers:
            swagger = os.path.join(self.prefix, swagger)
            pid = os.fork()
            if not pid:
                name = swagger.split('/')[2]
                print(('Starting server for: {} at: {}'.format(name, swagger)))
                resolver = MockResolver(mock_all='all')
                api_extra_args ={'resolver': resolver}

                app = connexion.FlaskApp(name,
                                         swagger_json=False,
                                         swagger_ui=False)

                app.add_api(swagger + '/swagger.yaml',
                            resolver_error=True,
                            validate_responses=True,
                            strict_validation=True,
                            **api_extra_args)

                app.run(port=port)

            else:
                try:
                    print('Wait for pinging server')
                    # Let the api initialize
                    time.sleep(2)
                    try:
                        t = urllib.request.urlopen('http://localhost:{}/'.format(port))
                        t.close()
                    except Exception as e:
                        print(('Fetch error: {}'.format(e)))

                    print('Killing child pid')
                    os.kill(pid, signal.SIGKILL)
                    print('Killed')

                    time.sleep(1)
                except (KeyboardInterrupt, Exception) as e:
                    os.kill(pid, signal.SIGKILL)
                    raise

            port +=1


if __name__ == '__main__':
    unittest.main()
