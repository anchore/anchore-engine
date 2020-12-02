import json
import os
import pytest

from anchore_engine.services.catalog.catalog_impl import load_policy_bundles


INPUT_BUNDLES_DIR = "bundles"


def get_mock_config_with_policy_bundles(dir, bundle_filenames):
    policy_bundles = []

    input_dir = dir.mkdir(INPUT_BUNDLES_DIR)
    # setup files to read and/or copy later
    mock_id = 0
    for bundle_filename in bundle_filenames:
        bundle_path = os.path.join(input_dir, bundle_filename)
        mock_body = json.dumps({
            "id": "0",
            "name": bundle_filename
        })
        with open(bundle_path, "w") as fp:
            fp.write(mock_body)
            fp.flush()

        policy_bundle = {}
        policy_bundle["active"] = len(policy_bundles) == 0
        policy_bundle["bundle_path"] = bundle_path
        policy_bundles.append(policy_bundle)

    return {
        "policy_bundles": policy_bundles
    }


@pytest.mark.parametrize("bundle_filenames", [
    (["first_bundle.json"])
])
def test_load_policy_bundles(tmpdir, bundle_filenames):
    config = get_mock_config_with_policy_bundles(tmpdir, bundle_filenames)
    policy_bundles = []
    bundles = []
    exceptions = []

    def process_bundle(policy_bundle, bundle):
        policy_bundles.append(policy_bundle)
        bundles.append(bundle)

    def process_exception(exception):
        exceptions.append(exception)

    load_policy_bundles(config, process_bundle, process_exception)

    assert len(policy_bundles) == len(bundle_filenames)
    assert len(bundles) == len(bundle_filenames)
    assert len(exceptions) == 0
