import pytest

from tests.functional.services.catalog.utils.api import objects
from tests.functional.services.utils import http_utils

test_params = [
    (
        "grypedb:vulnerabilities",
        "eef3b1bcd5728346cb1b30eae09647348bacfbde3ba225d70cb0374da249277c",
        "grypedb.tar.gz",
    ),
    ("test_text_bucket", "test", "test_text.txt"),
]


@pytest.mark.incremental
@pytest.mark.parametrize("bucket,archive_id, filename", test_params)
class TestObjectsRaw:
    @pytest.fixture(scope="class", autouse=True)
    def setup_and_teardown_tests(self, request):
        def _cleanup():
            for params in test_params:
                objects.delete_document(params[0], params[1])

        _cleanup()

        request.addfinalizer(_cleanup)

    @pytest.fixture
    def post_raw_document(self, request, expected_content):
        """
        Returns a function that
        """

        def _post_raw_document(bucket, archive_id, filename):
            content = expected_content(filename)
            resp = objects.add_raw_document(bucket, archive_id, content)

            request.addfinalizer(lambda: objects.delete_document(bucket, archive_id))

            return content, resp

        return _post_raw_document

    def test_post_raw_object(self, expected_content, bucket, archive_id, filename):
        content = expected_content(filename)
        create_doc_resp = objects.add_raw_document(bucket, archive_id, content)
        # content, create_doc_resp = post_raw_document(bucket, archive_id, filename)

        assert create_doc_resp == http_utils.APIResponse(200)

        resp_bucket, resp_archive = create_doc_resp.body.split("/")[-2::1]
        assert resp_bucket == bucket
        assert resp_archive == archive_id

    def test_get_raw_object(self, expected_content, bucket, archive_id, filename):
        content = expected_content(filename)
        object_response = objects.get_raw_document(bucket, archive_id)

        assert object_response == http_utils.APIResponse(200)
        assert object_response.body == content


class TestFailedGet:
    def test_failed_get(self):
        with pytest.raises(http_utils.RequestFailedError):
            objects.get_raw_document("test_expected_failure", "test")
