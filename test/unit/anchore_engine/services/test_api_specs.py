"""
Brings up each api in a test process to ensure spec is clean and works
"""

import pytest
import connexion
from connexion.mock import MockResolver
import os
import signal
import time
from test.utils import init_test_logging
from anchore_engine.subsys import logger

init_test_logging()

prefix = os.getcwd()

service_swaggers = [
    'anchore_engine/services/apiext/swagger/swagger.yaml',
    'anchore_engine/services/catalog/swagger/swagger.yaml',
    'anchore_engine/services/simplequeue/swagger/swagger.yaml',
    'anchore_engine/services/analyzer/swagger/swagger.yaml',
    'anchore_engine/services/policy_engine/swagger/swagger.yaml',
    'anchore_engine/services/kubernetes_webhook/swagger/swagger.yaml'
]

def test_api_service():
    """
    Creates a mocked interface for each specified swagger spec and runs a server with a forked process to ensure swagger validates fully.

    :return:
    """

    port = 8081

    for swagger in service_swaggers:
        pid = os.fork()
        if not pid:
            name = swagger.rsplit('/', 3)[2]
            logger.info(('Starting server for: {} at: {}'.format(name, swagger)))
            resolver = MockResolver(mock_all='all')
            api_extra_args = {'resolver': resolver}

            app = connexion.FlaskApp(name,
                                     swagger_json=False,
                                     swagger_ui=False)

            app.add_api(swagger,
                        resolver_error=True,
                        validate_responses=True,
                        strict_validation=True,
                        **api_extra_args)

            app.run(port=port)

        else:
            try:
                logger.info('Wait for pinging server of pid: {}'.format(pid))
                # Let the api initialize
                retries = 3
                killed = False

                for i in range(retries):
                    time.sleep(2)
                    proc_id, status = os.waitpid(pid, os.WNOHANG)

                    logger.info('Child pid: {}. Status = {}'.format(pid, status))
                    if proc_id == 0 and status == 0:
                        try:
                            logger.info('Killing pid {}'.format(pid))
                            os.kill(pid, signal.SIGTERM)
                            killed = True
                        except ProcessLookupError:
                            logger.info('Process {} not found, skipping kill'.format(pid))
                        finally:
                            break
                    elif status != 0 and killed:
                        logger.info('Confirmed child pid killed')
                        break
                    else:
                        pytest.fail('Mock service for {} failed to start properly'.format(swagger))
                        break
            except ProcessLookupError:
                logger.info('Process {} not found. Exiting cleanly')
            except (KeyboardInterrupt, Exception):
                raise
            finally:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    # This is expected
                    pass
                except:
                    logger.exception("Failed to kill child process")

