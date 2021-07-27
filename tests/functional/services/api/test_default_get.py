from tests.functional.services.utils.http_utils import APIResponse, http_get


class TestDefaultAPIGetReturns200:
    """
    This is for GET methods on endpoints under the "Default" section of the Swagger Spec
    Note: only run as admin right now
    """

    def test_root(self):
        resp = http_get([])
        assert resp == APIResponse(200)

    def test_health(self):
        resp = http_get(["health"])
        assert resp == APIResponse(200)

    def test_version(self):
        resp = http_get(["version"])
        assert resp == APIResponse(200)
