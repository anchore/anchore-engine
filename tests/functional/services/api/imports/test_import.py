import json

import pytest

from anchore_engine.subsys import logger
from tests.functional.services.api import imports
from tests.functional.services.utils.http_utils import (
    APIResponse,
    http_del,
    http_get,
    http_post,
    http_post_bytes,
)

logger.enable_test_logging(level="info")


@pytest.fixture
def module_path(request):
    return request.module.__file__


@pytest.fixture()
def begin_import() -> APIResponse:
    logger.info("Creating import operation.")
    import_response = http_post(["imports", "images"], payload={})
    yield import_response
    logger.info("Deleting import operation.")
    delete_response = http_del(["imports", "images", import_response.body["uuid"]])
    if delete_response.code == 200:
        logger.info("Deletion successful.")
    else:
        logger.info(f"Deletion failed! Response: {delete_response.body}")


@pytest.mark.incremental
@pytest.mark.parametrize(
    "syft_json_name, dockerfile_name",
    [
        ("syft-0.12.2-lean.json", "Dockerfile_lean"),
    ],
)
class TestImports:
    def test_begin_imports(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        begin_import: APIResponse,
    ):
        assert begin_import.code == 200
        assert begin_import.body["status"] == "pending"
        assert "uuid" in begin_import.body

    def test_delete_imports(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        begin_import: APIResponse,
    ):
        import_response = http_post(["imports", "images"], payload={})
        delete_response = http_del(["imports", "images", import_response.body["uuid"]])
        assert delete_response.code == 200

    def test_list_imports(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        begin_import: APIResponse,
    ):
        operation_uuid = begin_import.body["uuid"]
        list_imports_response = http_get(["imports", "images"])
        assert list_imports_response.code == 200
        uuids = [x["uuid"] for x in list_imports_response.body]
        assert operation_uuid in uuids

    def test_upload_dockerfile(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        dockerfile = imports.load_file(module_path, dockerfile_name)
        result: APIResponse = http_post(
            ["imports", "images", begin_import.body["uuid"], "dockerfile"],
            payload=dockerfile,
        )
        assert result.code == 200

    def test_list_dockerfiles(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        operation_uuid = begin_import.body["uuid"]
        dockerfile = imports.load_file(module_path, dockerfile_name)
        result: APIResponse = http_post(
            ["imports", "images", operation_uuid, "dockerfile"], payload=dockerfile
        )
        assert result.code == 200
        list_response = http_get(["imports", "images", operation_uuid, "dockerfile"])
        assert list_response.code == 200
        assert list_response.body[0]["digest"] == result.body["digest"]

    def test_upload_packages(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        syft_json = imports.load_file(module_path, syft_json_name)
        packages = json.loads(syft_json)
        result: APIResponse = http_post(
            ["imports", "images", begin_import.body["uuid"], "packages"],
            payload=packages,
        )
        assert result.code == 200

    def test_list_packages(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        syft_json = imports.load_file(module_path, syft_json_name)
        operation_uuid = begin_import.body["uuid"]
        packages = json.loads(syft_json)
        result: APIResponse = http_post(
            ["imports", "images", operation_uuid, "packages"], payload=packages
        )
        assert result.code == 200
        list_response = http_get(["imports", "images", operation_uuid, "packages"])
        assert list_response.code == 200
        assert list_response.body[0]["digest"] == result.body["digest"]

    def test_upload_manifest(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        """
        Note copied from test script `scripts/tests/image_import/test_import.py`:
        Load from the file as bytes arrays instead of json objects to ensure that the
        digest computation matches and isn't impacted by any python re-ordering of
        keys or adding/removing whitespace. This should enable the output of
        `sha256sum <file>` to match the digests returned during this test
        """
        syft_json = imports.load_file(module_path, syft_json_name)
        manifest = imports.extract_syft_metadata(syft_json)["manifest"]
        result: APIResponse = http_post_bytes(
            ["imports", "images", begin_import.body["uuid"], "manifest"],
            payload=manifest,
        )
        assert result.code == 200

    def test_list_manifests(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        operation_uuid = begin_import.body["uuid"]
        syft_json = imports.load_file(module_path, syft_json_name)
        manifest = imports.extract_syft_metadata(syft_json)["manifest"]
        result: APIResponse = http_post_bytes(
            ["imports", "images", operation_uuid, "manifest"], payload=manifest
        )
        assert result.code == 200
        list_response = http_get(["imports", "images", operation_uuid, "manifest"])
        assert list_response.code == 200
        assert list_response.body[0]["digest"] == result.body["digest"]

    def test_upload_image_config(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        """
        Note copied from test script `scripts/tests/image_import/test_import.py`:
        Load from the file as bytes arrays instead of json objects to ensure that the
        digest computation matches and isn't impacted by any python re-ordering of
        keys or adding/removing whitespace. This should enable the output of
        `sha256sum <file>` to match the digests returned during this test
        """
        syft_json = imports.load_file(module_path, syft_json_name)
        image_config = imports.extract_syft_metadata(syft_json)["image_config"]
        result: APIResponse = http_post_bytes(
            ["imports", "images", begin_import.body["uuid"], "image_config"],
            payload=image_config,
        )
        assert result.code == 200

    def test_list_image_configs(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        operation_uuid = begin_import.body["uuid"]
        syft_json = imports.load_file(module_path, syft_json_name)
        image_config = imports.extract_syft_metadata(syft_json)["image_config"]
        result: APIResponse = http_post_bytes(
            ["imports", "images", operation_uuid, "image_config"],
            payload=image_config,
        )
        assert result.code == 200
        list_response = http_get(["imports", "images", operation_uuid, "image_config"])
        assert list_response.code == 200
        assert list_response.body[0]["digest"] == result.body["digest"]

    def test_full_upload(
        self,
        syft_json_name: str,
        dockerfile_name: str,
        module_path: str,
        begin_import: APIResponse,
    ):
        operation_uuid = begin_import.body["uuid"]
        syft_json = imports.load_file(module_path, syft_json_name)
        dockerfile = imports.load_file(module_path, dockerfile_name)
        metadata = imports.extract_syft_metadata(syft_json)
        # upload dockerfile
        upload_dockerfile_response: APIResponse = http_post(
            ["imports", "images", operation_uuid, "dockerfile"],
            payload=dockerfile,
        )
        assert upload_dockerfile_response.code == 200
        dockerfile_digest = upload_dockerfile_response.body["digest"]
        # upload packages
        packages = json.loads(syft_json)
        upload_packages_response: APIResponse = http_post(
            ["imports", "images", operation_uuid, "packages"], payload=packages
        )
        assert upload_packages_response.code == 200
        packages_digest = upload_packages_response.body["digest"]
        # upload manifest
        upload_manifest_response: APIResponse = http_post_bytes(
            ["imports", "images", operation_uuid, "manifest"],
            payload=metadata["manifest"],
        )
        assert upload_manifest_response.code == 200
        manifest_digest = upload_manifest_response.body["digest"]
        # upload image config
        upload_config_response: APIResponse = http_post_bytes(
            ["imports", "images", operation_uuid, "image_config"],
            payload=metadata["image_config"],
        )
        assert upload_config_response.code == 200
        image_config_digest = upload_config_response.body["digest"]
        # upload image
        payload = {
            "source": {
                "import": {
                    "digest": metadata["digest"],
                    "local_image_id": metadata["local_image_id"],
                    "contents": {
                        "packages": packages_digest,
                        "dockerfile": dockerfile_digest,
                        "manifest": manifest_digest,
                        "image_config": image_config_digest,
                    },
                    "tags": metadata["tags"],
                    "operation_uuid": operation_uuid,
                }
            },
            "annotations": {"testkey1": "testvalue1", "testkey2": "testvalue2"},
        }
        image_upload_response = http_post(["images"], payload=payload)
        assert image_upload_response.code == 200
        # check image uploaded
        image_list_response = http_get(["images", metadata["digest"]])
        assert image_list_response.code == 200
