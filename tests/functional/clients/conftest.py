import importlib.util
import json
import os
from functools import lru_cache
from os.path import join

import pytest

from .scripts import standalone

pre_baked_images = {
    "centos8": {
        "registry": "docker.io",
        "repo": "centos",
        "tag": "centos8",
        "digest": "sha256:85313b812ad747dd19cf18078795b576cc4ae9cd2ca2ccccd7b5c12722b2effd",
        "image_source": "registry",
        "schema_version": "2",
    },
    "alpine2.6": {
        "registry": "docker.io",
        "repo": "alpine",
        "tag": "2.6",
        "digest": "sha256:e9cec9aec697d8b9d450edd32860ecd363f2f3174c8338beb5f809422d182c63",
        "image_source": "registry",
        "schema_version": "1",
    },
    "lean": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "lean",
        "digest": "sha256:8d0e40d8e013bb0cda3d279b5021c473885c079e94010fd2208235d56982486f",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "py38": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "py38",
        "digest": "sha256:65e79fb7397ed96bd84656a664ac9978057930d90b2d5fde5e92a58adbee657c",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "npm": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "npm",
        "digest": "sha256:905a2bf5f3adf8ba8f1d4391cfb4a3e6bd671e0b2ec2f488071679a5f578c7d7",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "java": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "java",
        "digest": "sha256:9f453a37ea62976dd0f6b8ca4da2010cc01c3988f2e8c290044576d936bae710",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "stretch-slim": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "debian-stretch-slim",
        "digest": "sha256:cd74be1a65a7c7f07aa9952f622097a6452012fea741fbdade0e763edaa55ba0",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "rpm": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "centos8",
        "digest": "sha256:96d136c9cbaf22d73010e3e79e748e7772143fd9a584f8898d2f122cc5da1206",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "busybox": {
        "registry": "docker.io",
        "repo": "busybox",
        "tag": "1.32.0-glibc",
        "digest": "sha256:6e6d13055ed81b7144afaad15150fc137d4f639482beb311aaa097bc57e3cb80",
        "image_source": "registry",
        "schema_version": "v2",
    },
    # skopeo inspect --override-os linux  docker://anchore/test_images@sha256:bf25131f6f6ba5ca531b2075424bfb25c36cc01f8e83cc3c759c404870a64e38 --raw
    "bin": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "bin",
        "digest": "sha256:bf25131f6f6ba5ca531b2075424bfb25c36cc01f8e83cc3c759c404870a64e38",
        "image_source": "registry",
        "schema_version": "v2",
    },
    # skopeo inspect --override-os linux  docker://anchore/test_images@sha256:bfbc9520743a4601da82c24958e194d55e45b8cab7c5b466f6ac81c90308749f --raw
    "ownership-overlap": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "ownership-overlap",
        "digest": "sha256:bfbc9520743a4601da82c24958e194d55e45b8cab7c5b466f6ac81c90308749f",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "suids": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "suids",
        "digest": "sha256:1d0df8e380b947e9f76a1082cc550c3634dbbcfeb78e4c4874eeb149f377326d",
        "image_source": "registry",
        "schema_version": "v2",
    },
    "secrets": {
        "registry": "docker.io",
        "repo": "anchore/test_images",
        "tag": "secrets",
        "digest": "sha256:0be667e0698fb204d2a6eaf42be8bf15db7edaf256c07e40caecbbcdbf6aad52",
        "image_source": "registry",
        "schema_version": "v2",
    },
}


def create_cache_directories(
    registry=None,
    repo=None,
    digest=None,
    image_source=None,
    schema_version=None,
    cache_root=None,
    **kw
):
    """
    Create a set of directories needed to save the data, skip creation if they
    are there
    """
    # The digest needs to get split because otherwise the analyzer splits on
    # ':' creating a path that is incorrect and causing failures. So this gets
    # split here, avoiding the problem
    digest = digest.split(":")[-1]
    relative_cache_path = "{image_source}/{registry}/{repo}/{digest}/{schema_version}"
    relative_cache_path = relative_cache_path.format(
        image_source=image_source,
        registry=registry,
        repo=repo,
        digest=digest,
        schema_version=schema_version,
    )
    cache_path = join(cache_root, relative_cache_path)
    os.makedirs(cache_path, exist_ok=True)

    return cache_path


@pytest.fixture
def hints_image(monkeypatch, tmpdir):
    """
    This fixture is *very* expensive. Sorry. There is no way around it. The
    hintsfile functionality requires the image to be analyzed every single
    time. Compensate with the smallest images possible
    """

    def func(contents, image):
        work_dir = tmpdir.strpath
        path = os.path.join(work_dir, "anchore_hints.json")
        with open(path, "w") as _f:
            json.dump(contents, _f)
        monkeypatch.setenv("ANCHORE_TEST_HINTSFILE", path)
        image_kwargs = pre_baked_images[image]
        standalone.main(
            work_dir=work_dir,
            localconfig={"services": {"analyzer": {"enable_hints": True}}},
            **image_kwargs
        )
        results_path = join(work_dir, "result.py")
        spec = importlib.util.spec_from_file_location(
            "functional_results", results_path
        )
        functional_results = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(functional_results)
        # After importing the result as a Python module, the standalone script
        # will assign the return value to `result` which is a single item in
        # a list. Return the first item in that list. If this ever fails, is
        # because the `result.py` file doesn't comply with that format
        return functional_results.result[0]

    return func


@pytest.fixture(scope="session")
def analyzed_data(request):
    @lru_cache(maxsize=10)
    def retrieve_cache(image="centos8"):
        """
        The cache path gets computed by looking at the path, composed from all the arguments::

            <image_source>/<registry>/<repo>/<split digest>/<schema_version>

        For example::

            registry/docker.io/centos/85a8df7bk3j28d7f0asd8/2

        If the cache is a MISS, then the  `analyze_image()` will get called to
        produce a result module than it will get loaded and returned.

        The cache can be blown away by using ``pytest --cache-clear``. Absolute
        path to the cache directory is at the root of the project:

            {ROOT}/.pytest_cache/d/analyzer
        """
        image_kwargs = pre_baked_images[image]
        cache_root = request.config.cache.makedir("analyzer").strpath
        cache_path = create_cache_directories(cache_root=cache_root, **image_kwargs)
        results_path = join(cache_path, "result.py")
        if not os.path.exists(results_path):
            standalone.main(work_dir=cache_path, **image_kwargs)

        spec = importlib.util.spec_from_file_location(
            "functional_results", results_path
        )
        functional_results = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(functional_results)
        # After importing the result as a Python module, the standalone script
        # will assign the return value to `result` which is a single item in
        # a list. Return the first item in that list. If this ever fails, is
        # because the `result.py` file doesn't comply with that format
        return functional_results.result[0]

    return retrieve_cache
