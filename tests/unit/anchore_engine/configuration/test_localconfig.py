import json
import os
from pathlib import Path

import pytest

from anchore_engine.configuration.localconfig import (
    DEFAULT_CONFIG,
    get_config,
    load_defaults,
    load_filepath_to_config,
    load_policy_bundle_paths,
    load_policy_bundles,
    validate_config,
)

DEFAULT_CONFIG_FN = "config.yaml"
DEFAULT_ANALYZER_CONFIG_FN = "analyzer_config.yaml"
DEFAULT_POLICY_BUNDLE_FN = "anchore_default_bundle.yaml"
CUSTOM_POLICY_BUNDLE_FN = "anchore_custom_bundle.yaml"

ANALYZER_CONFIG_TEXT = "analyzer\n"
POLICY_BUNDLE_TEXT = "policy bundle\n"

INPUT_CONFIG_DIR = "input_config"
INPUT_BUNDLES_DIR_ROOT = "input_bundles"
OUTPUT_BUNDLES_DIR = "bundles"


@pytest.fixture
def mock_default_config(tmpdir):
    config_copy = DEFAULT_CONFIG.copy()
    config_fn = tmpdir.join(DEFAULT_CONFIG_FN)
    with open(config_fn.strpath, "w") as fp:
        fp.write(str(config_copy))
        fp.flush()


def mock_test_files(input_dir, config_filenames):
    # setup files to read and/or copy later
    for config_filename in config_filenames:
        mock_test_file(input_dir, config_filename)


def mock_test_file(input_dir, config_filename):
    # setup files to read and/or copy later
    Path(input_dir.strpath + "/" + config_filename).touch()


def get_mock_config_with_policy_bundles(dir, bundle_filenames, simulate_exception):
    policy_bundles = []

    input_dir = dir.mkdir(OUTPUT_BUNDLES_DIR)
    # setup files to read and/or copy later
    mock_id = 0
    for bundle_filename in bundle_filenames:
        bundle_path = os.path.join(input_dir, bundle_filename)
        if simulate_exception:
            mock_body = "not json"
        else:
            mock_body = json.dumps({"id": str(mock_id), "name": bundle_filename})
        mock_id += 1
        with open(bundle_path, "w") as fp:
            fp.write(mock_body)
            fp.flush()

        policy_bundle = {}
        # Just make the first bundle active since it's arbitrary for these tests
        policy_bundle["active"] = len(policy_bundles) == 0
        policy_bundle["bundle_path"] = bundle_path
        policy_bundles.append(policy_bundle)

    return {"policy_bundles": policy_bundles}


def test_empty_src_dirs(mock_default_config, tmpdir):
    # setup the default config
    load_defaults(configdir=tmpdir)

    # function under test
    load_policy_bundle_paths(src_dirs=[])

    # get and validate the relevant config bits
    config = get_config()
    assert config["policy_bundles"] is None


@pytest.mark.parametrize(
    "config_filename_sets",
    [
        ([[]]),
        ([["anchore_default_bundle.json"]]),
        ([["anchore_default_bundle.json", "second_bundle.json"]]),
        (
            [
                ["anchore_default_bundle.json", "second_bundle.json"],
                ["third_bundle.json", "fourth_bundle.json"],
                ["fifth_bundle.json"],
            ]
        ),
    ],
)
def test_load_policy_bundle_paths(mock_default_config, tmpdir, config_filename_sets):
    # setup files to read
    src_dirs = []
    i = 0
    for set in config_filename_sets:
        input_dir = tmpdir.mkdir(INPUT_BUNDLES_DIR_ROOT + "_" + str(i))
        i += 1
        mock_test_files(input_dir, set)
        src_dirs.append(input_dir.strpath)

    # setup the expected output. We will expect to see output_dir_name contain the
    # files in config_filenames_flat
    output_dir_name = tmpdir.strpath + "/bundles"
    config_filenames_flat = [
        filename for set in config_filename_sets for filename in set
    ]

    # setup the default config
    load_defaults(configdir=tmpdir)

    # function under test
    load_policy_bundle_paths(src_dirs=src_dirs)

    # get and validate the relevant config bits
    config = get_config()
    assert config["policy_bundles"] is not None
    assert len(config["policy_bundles"]) == len(config_filenames_flat)
    for config_filename in config_filenames_flat:
        policy_bundle = next(
            policy_bundle
            for policy_bundle in config["policy_bundles"]
            if policy_bundle["bundle_path"] == output_dir_name + "/" + config_filename
        )
        assert policy_bundle is not None
        if config_filename == "anchore_default_bundle.json":
            assert policy_bundle["active"]
        else:
            assert not policy_bundle["active"]
        assert os.path.exists(policy_bundle["bundle_path"])


@pytest.mark.parametrize(
    "config_key, config_filename",
    [
        ("anchore_scanner_analyzer_config_file", "analyzer_config.yaml"),
        ("anchore_scanner_analyzer_config_file", "other_config.yaml"),
    ],
)
def test_load_filepath_to_config(
    mock_default_config, tmpdir, config_key, config_filename
):
    # setup files to read
    input_dir = tmpdir.mkdir(INPUT_CONFIG_DIR)
    mock_test_file(input_dir, config_filename)
    output_dir_name = tmpdir.strpath

    # setup the default config
    load_defaults(configdir=tmpdir)

    load_filepath_to_config(config_key, config_filename, src_dir=input_dir.strpath)
    config = get_config()
    assert config["anchore_scanner_analyzer_config_file"] is not None
    assert (
        config["anchore_scanner_analyzer_config_file"]
        == output_dir_name + "/" + config_filename
    )
    assert os.path.exists(config["anchore_scanner_analyzer_config_file"])


@pytest.mark.parametrize(
    "bundle_filenames, simulate_exception, expected_bundles, expected_exceptions",
    [
        (["first_bundle.json"], False, 1, 0),
        (["first_bundle.json", "first_bundle.json"], False, 2, 0),
        (["first_bundle.json"], True, 0, 1),
    ],
)
def test_load_policy_bundles(
    tmpdir, bundle_filenames, simulate_exception, expected_bundles, expected_exceptions
):
    config = get_mock_config_with_policy_bundles(
        tmpdir, bundle_filenames, simulate_exception
    )
    policy_bundles = []
    bundles = []
    exceptions = []

    def process_bundle(policy_bundle, bundle):
        policy_bundles.append(policy_bundle)
        bundles.append(bundle)

    def process_exception(exception):
        exceptions.append(exception)

    load_policy_bundles(config, process_bundle, process_exception)

    assert len(policy_bundles) == expected_bundles
    assert len(bundles) == expected_bundles
    assert len(exceptions) == expected_exceptions


def test_validate_max_compressed_image_size_mb():
    validate_config({"max_compressed_image_size_mb": 54}, {})

    validate_config({"max_compressed_image_size_mb": -1}, {})

    with pytest.raises(Exception):
        validate_config({"max_compressed_image_size_mb": "Test"}, {})
