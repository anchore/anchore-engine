"""
Brings up each api in a test process to ensure spec is clean and works
"""

import os

import connexion
import pytest
from connexion.mock import MockResolver

from tests.utils import init_test_logging

init_test_logging()

prefix = os.getcwd()

service_swaggers = [
    "anchore_engine/services/apiext/swagger/swagger.yaml",
    "anchore_engine/services/catalog/swagger/swagger.yaml",
    "anchore_engine/services/simplequeue/swagger/swagger.yaml",
    "anchore_engine/services/analyzer/swagger/swagger.yaml",
    "anchore_engine/services/policy_engine/swagger/swagger.yaml",
]


@pytest.mark.parametrize("service", service_swaggers)
def test_api_service(service):
    """
    Creates a mocked interface for each specified swagger spec and creates
    a server to ensure swagger validates fully.

    If invalid specs are detected the spec will raise `InvalidSpecification`.

    Further enhancement of this test is to make actual requests to the Apps
    generated.
    """

    port = 8081
    name = service.rsplit("/", 3)[2]
    resolver = MockResolver(mock_all="all")
    api_extra_args = {"resolver": resolver}

    options = {"serve_spec": False, "swagger_ui": False}
    app = connexion.FlaskApp(name, options=options)

    app.add_api(
        service,
        resolver_error=True,
        validate_responses=True,
        strict_validation=True,
        **api_extra_args
    )

    client = app.app.test_client()
    # potential enhancment would be to create a request like:
    #     response = client.get('/health')
    #     assert response.status_code == 200
