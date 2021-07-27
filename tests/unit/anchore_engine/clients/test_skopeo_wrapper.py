import gzip
import json
import os
import pathlib
import tarfile

import pytest

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
        with open(destination_path, "w") as _f:
            _f.write(self.content)


@pytest.fixture
def blobs():
    def return_value(*digests):
        def digest_to_blob(digest: str):
            return {"digest": digest, "urls": ["https://example.fooo.bar"]}

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
                "size": 504,
            }
        ],
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
                "size": 354,
            },
            "layers": [
                {
                    "mediaType": layer_media_type,
                    "digest": "sha256:0e31ee8f400716f940be9db76d6eedb1a903860385b4ca8f70513012d53fe1f1",
                    "size": 103066803,
                    "urls": [
                        "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:0e31ee8f400716f940be9db76d6eedb1a903860385b4ca8f70513012d53fe1f1"
                    ],
                }
            ],
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
    monkeypatch.setattr(
        skopeo_wrapper, "urlretrieve", FakeUrlRetrieve(content=expected_blob_content)
    )

    skopeo_wrapper.fetch_oci_blobs(blobs_dir, blobs(blob_digest))

    results_path = os.path.join(blobs_dir, "sha256", blob_digest)
    assert os.path.exists(results_path)

    with open(results_path, "r") as _f:
        assert _f.read() == expected_blob_content


def test_fetch_oci_blobs_multiple_blobs(monkeypatch, tmpdir, blobs):
    blobs_dir = tmpdir.strpath
    tmpdir.mkdir("sha256")
    blob_digests = ["aaaa", "bbbb", "cccc"]
    expected_blob_content = "I'm a TAR!"
    monkeypatch.setattr(
        skopeo_wrapper, "urlretrieve", FakeUrlRetrieve(content=expected_blob_content)
    )

    skopeo_wrapper.fetch_oci_blobs(blobs_dir, blobs(*blob_digests))

    for digest in blob_digests:
        results_path = os.path.join(blobs_dir, "sha256", digest)
        assert os.path.exists(results_path)

        with open(results_path, "r") as _f:
            assert _f.read() == expected_blob_content


def test_fetch_oci_blobs_it_bombs(monkeypatch, blobs):
    monkeypatch.setattr(
        skopeo_wrapper, "urlretrieve", FakeUrlRetrieve(raises=TypeError)
    )
    skopeo_wrapper.fetch_oci_blobs("/some/path", blobs())


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
    initial_layer_media_type = (
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
    )

    with open(oci_index_file_path, "w") as _f:
        _f.write(oci_index)

    with open(oci_manifest_file_path, "w") as _f:
        _f.write(oci_manifest(layer_media_type=initial_layer_media_type))

    skopeo_wrapper.ensure_no_nondistributable_media_types(oci_index_file_path)

    expected_layer_media_type = "application/vnd.oci.image.layer.v1.tar+gzip"

    with open(oci_manifest_file_path, "r") as _f:
        assert _f.read() == oci_manifest(layer_media_type=expected_layer_media_type)


class TestIsGzip:
    def test_false(self):
        result = skopeo_wrapper.is_gzip("")
        assert result is False

    def test_false_with_existent_path(self, tmp_path):
        print(tmp_path)
        result = skopeo_wrapper.is_gzip(tmp_path)
        assert result is False

    def test_false_real_tar(self, tmpdir):
        file_name = tmpdir.join("blob")
        file_name.write("I'm a file")
        tar_file_name = tmpdir.join("test.tar")

        with tarfile.open(tar_file_name.strpath, "w") as _f:
            _f.addfile(tarfile.TarInfo(file_name.strpath), open(file_name))

        result = skopeo_wrapper.is_gzip(tar_file_name.strpath)
        assert result is False


def create_tar(checksum_path, text_file):
    with tarfile.open(checksum_path, "w") as _f:
        _f.addfile(tarfile.TarInfo(text_file), open(text_file))


def create_gzip(checksum_path):
    with gzip.open(checksum_path, "wb") as _f:
        _f.write(b"a gzipped file!")


def create_manifest(sha_path, checksums):
    manifest = {
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:0000XXXXX",
            "size": 8516,
        },
        "layers": [],
    }

    media_types = {
        "tar": "application/vnd.oci.image.layer.v1.tar",
        "gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
    }

    for checksum, metadata in checksums.items():
        if checksum == "manifest":
            continue
        mediaType = media_types[metadata.get("mediaType")]
        manifest["layers"].append(
            {"mediaType": mediaType, "digest": f"sha256:{checksum}", "size": 22528609}
        )

    manifest_sha = checksums["manifest"]
    manifest_path = os.path.join(sha_path.strpath, manifest_sha)

    with open(manifest_path, "w") as _f:
        json.dump(manifest, _f)

    return manifest_path


def index_json(checksum):
    """
    checksum: the digest of the manifest
    """
    return {
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{checksum}",
                "size": 1110,
            }
        ],
    }


def create_index(root_path, checksums):
    """
    Create an index.json with a manifest value
    """
    index_path = os.path.join(root_path, "index.json")

    manifest_sha = checksums["manifest"]
    content = index_json(manifest_sha)
    with open(index_path, "w") as _f:
        json.dump(content, _f)

    return index_path


def create_oci(tmpdir, checksums):
    """
    root_path/blobs/sha256/<checksum>

    manifest = {
         "manifest": "sha256:000X",
        "sha256:0001": {"mediaType": "tar", "filetype": "tar"}
    }

    """
    paths_created = {}

    # Hard code the manifest, the value doesn't matter
    checksums["manifest"] = "00001manifest"

    root_path = tmpdir.strpath
    paths_created["root"] = root_path

    # create the blobs/sha256 dir
    sha_path = tmpdir.mkdir("blobs").mkdir("sha256")
    tmp_root_path = tmpdir.mkdir("tmp")

    # create a temporary text file
    text_file = tmp_root_path.join("test.txt")
    text_file.write("test file!")

    # create the index.json and manifest
    paths_created["index.json"] = create_index(root_path, checksums)
    paths_created["manifest"] = create_manifest(sha_path, checksums)

    for checksum, value in checksums.items():
        # skip the JSON manifest
        if checksum == "manifest":
            continue
        checksum_path = os.path.join(sha_path, checksum)
        paths_created[checksum] = checksum_path
        if value["filetype"] == "tar":
            create_tar(checksum_path, text_file.strpath)
        elif value["filetype"] == "gzip":
            create_gzip(checksum_path)
        else:
            # create a shasum but as plain text
            sha_path.join(checksum_path).write("plain text!")

    return paths_created


@pytest.fixture
def oci(tmpdir):
    return lambda checksums: create_oci(tmpdir, checksums)


# test values
#
manifest_test_cases = [
    ("tar", "tar", "application/vnd.oci.image.layer.v1.tar"),
    ("gzip", "tar", "application/vnd.oci.image.layer.v1.tar"),
    ("gzip", "gzip", "application/vnd.oci.image.layer.v1.tar+gzip"),
    ("tar", "gzip", "application/vnd.oci.image.layer.v1.tar+gzip"),
]


@pytest.mark.parametrize("mediaType,filetype,expected", manifest_test_cases)
def test_correct_oci_media_types(oci, mediaType, filetype, expected):
    oci_paths = oci(
        {
            "00002zxcv": {"mediaType": mediaType, "filetype": filetype},
        }
    )

    skopeo_wrapper.ensure_layer_media_types_are_correct(oci_paths["root"])

    with open(oci_paths["manifest"], "r") as _f:
        manifest = json.load(_f)

    assert manifest["layers"][0]["mediaType"] == expected
