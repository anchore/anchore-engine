import os
import pytest
import pathlib
import json
from anchore_engine.clients import skopeo_wrapper


oci_manifest_digest = "2a8ca7db7332bc6c3b825a4540c33b47ad588947aa130f07b7493a863daa3ba3"

# fake urlretrieve class


class FakeUrlRetrieve:
    """
    >>> fake = FakeUlrRetrieve(raises=TypeError)
    >>> fake(url, path)
    ... BOMB!
    """

    def __init__(self, raises=None, content=""):
        self.raises = raises
        self.content = content

    def __call__(self, url, destination_path):
        if self.raises is not None:
            raise self.raises
        with open(destination_path, 'w') as _f:
            _f.write(self.content)


@pytest.fixture
def blobs():
    def return_value(*digests):
        def digest_to_blob(digest: str):
            return {
                "digest": digest,
                "urls": ["https://example.fooo.bar"]
            }

        return list(map(digest_to_blob, digests))

    return return_value


@pytest.fixture
def oci_index():
    index = {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:{}".format(oci_manifest_digest),
                "size": 504
            }
        ]
    }

    return json.dumps(index)


@pytest.fixture
def oci_manifest():
    def return_value(layer_media_type: str):
        manifest = {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:b4382afec288f18a7255c91b9c5dfe37d66dc1aca7be8cefdbbd5b14ae794d3f",
                "size": 354
            },
            "layers": [
                {
                    "mediaType": layer_media_type,
                    "digest": "sha256:0e31ee8f400716f940be9db76d6eedb1a903860385b4ca8f70513012d53fe1f1",
                    "size": 103066803,
                    "urls": [
                        "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:0e31ee8f400716f940be9db76d6eedb1a903860385b4ca8f70513012d53fe1f1"
                    ]
                }
            ]
        }

        return json.dumps(manifest)

    return return_value


def test_fetch_oci_blobs_no_blobs(tmpdir):
    blobs_dir = tmpdir.strpath
    blobs = []

    skopeo_wrapper.fetch_oci_blobs(blobs_dir, blobs)

    assert len(os.listdir(blobs_dir)) == 0


def test_fetch_oci_blobs_single_blob(monkeypatch, tmpdir, blobs):
    blobs_dir = tmpdir.strpath
    tmpdir.mkdir("sha256")
    blob_digest = "ffff"
    expected_blob_content = "I'm a TAR!"
    monkeypatch.setattr(skopeo_wrapper, 'urlretrieve', FakeUrlRetrieve(content=expected_blob_content))

    skopeo_wrapper.fetch_oci_blobs(blobs_dir, blobs(blob_digest))

    results_path = os.path.join(blobs_dir, 'sha256', blob_digest)
    assert os.path.exists(results_path)

    with open(results_path, 'r') as _f:
        assert _f.read() == expected_blob_content


def test_fetch_oci_blobs_multiple_blobs(monkeypatch, tmpdir, blobs):
    blobs_dir = tmpdir.strpath
    tmpdir.mkdir("sha256")
    blob_digests = ["aaaa", "bbbb", "cccc"]
    expected_blob_content = "I'm a TAR!"
    monkeypatch.setattr(skopeo_wrapper, 'urlretrieve', FakeUrlRetrieve(content=expected_blob_content))

    skopeo_wrapper.fetch_oci_blobs(blobs_dir, blobs(*blob_digests))

    for digest in blob_digests:
        results_path = os.path.join(blobs_dir, 'sha256', digest)
        assert os.path.exists(results_path)

        with open(results_path, 'r') as _f:
            assert _f.read() == expected_blob_content


def test_fetch_oci_blobs_it_bombs(monkeypatch, blobs):
    monkeypatch.setattr(skopeo_wrapper, 'urlretrieve', FakeUrlRetrieve(raises=TypeError))
    skopeo_wrapper.fetch_oci_blobs('/some/path', blobs())


def test_get_digest_value_with_alg():
    digest = "ffff"
    digest_with_alg = "sha256:{}".format(digest)

    result = skopeo_wrapper.get_digest_value(digest_with_alg)
    assert result == digest


def test_get_digest_value_without_alg():
    digest = "ffff"

    result = skopeo_wrapper.get_digest_value(digest)
    assert result == digest


def test_ensure_no_nondistributable_media_types(tmpdir, oci_index, oci_manifest):
    oci_dir = tmpdir.strpath
    oci_index_file_path = os.path.join(oci_dir, "index.json")
    blobs_dir = os.path.join(oci_dir, "blobs")
    sha256_dir = os.path.join(blobs_dir, "sha256")
    pathlib.Path(sha256_dir).mkdir(parents=True, exist_ok=True)
    oci_manifest_file_path = os.path.join(sha256_dir, oci_manifest_digest)
    initial_layer_media_type = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"

    with open(oci_index_file_path, "w") as _f:
        _f.write(oci_index)

    with open(oci_manifest_file_path, "w") as _f:
        _f.write(oci_manifest(layer_media_type=initial_layer_media_type))

    skopeo_wrapper.ensure_no_nondistributable_media_types(oci_index_file_path)

    expected_layer_media_type = "application/vnd.oci.image.layer.v1.tar+gzip"

    with open(oci_manifest_file_path, "r") as _f:
        assert _f.read() == oci_manifest(layer_media_type=expected_layer_media_type)
