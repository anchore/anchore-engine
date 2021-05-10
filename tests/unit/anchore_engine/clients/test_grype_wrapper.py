import anchore_engine.configuration.localconfig
import os
import pytest
import shutil
import sqlalchemy

from anchore_engine.clients import grype_wrapper
from anchore_engine.clients.grype_wrapper import ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE

TEST_DATA_RELATIVE_PATH = "../../data/grype_db/"
GRYPE_ARCHIVE_FILE_NAME = "grype_db_test_archive.tar.gz"

GRYPE_DB_DIR = "grype_db/"
OLD_VERSION_NAME = "old_version"
NEW_VERSION_NAME = "new_version"


def get_test_file_path(basename: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TEST_DATA_RELATIVE_PATH, basename
    )


def get_test_sbom(sbom_file_name):
    full_sbom_path = get_test_file_path(sbom_file_name)
    with open(full_sbom_path, "r") as read_file:
        return read_file.read().replace("\n", "")


def get_test_sbom_file(sbom_file_name):
    full_sbom_path = get_test_file_path(sbom_file_name)
    return full_sbom_path


@pytest.fixture
def grype_db_parent_dir(tmp_path):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    localconfig["service_dir"] = tmp_path
    anchore_engine.configuration.localconfig.localconfig = localconfig

    return os.path.join(tmp_path, GRYPE_DB_DIR)


@pytest.fixture
def grype_db_archive(tmp_path):
    input_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(input_dir):
        os.mkdir(input_dir)
    shutil.copy(get_test_file_path(GRYPE_ARCHIVE_FILE_NAME), input_dir)
    return os.path.join(input_dir, "grype_db_test_archive.tar.gz")


@pytest.fixture
def grype_db_dir(tmp_path):
    parent_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)
    input_dir = os.path.join(parent_dir, NEW_VERSION_NAME)
    shutil.copytree(get_test_file_path(NEW_VERSION_NAME), input_dir)
    return input_dir


@pytest.fixture
def old_grype_db_dir(tmp_path):
    parent_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)
    input_dir = os.path.join(parent_dir, OLD_VERSION_NAME)
    shutil.copytree(get_test_file_path(OLD_VERSION_NAME), input_dir)
    return input_dir


def test_get_default_cache_dir_from_config(grype_db_parent_dir, tmp_path):
    # Function under test
    local_db_dir = grype_wrapper._get_default_grype_db_dir_from_config()

    # Validate the grype db dir exists and is in the correct location
    assert os.path.exists(local_db_dir)
    assert local_db_dir == grype_db_parent_dir


def test_move_grype_db_archive(tmp_path, grype_db_archive):
    # Setup the output dir to be copied into
    output_dir = os.path.join(tmp_path, "output")
    os.mkdir(output_dir)

    # Function under test
    grype_db_archive_copied_file_location = grype_wrapper._move_grype_db_archive(
        grype_db_archive, output_dir
    )

    # Validate archive was copied and to the correct location
    assert os.path.exists(grype_db_archive_copied_file_location)
    assert grype_db_archive_copied_file_location == os.path.join(
        output_dir, "grype_db_test_archive.tar.gz"
    )


def test_move_missing_grype_db_archive(tmp_path):
    # Setup non-existent input archive and real output dir
    missing_output_archive = "/does/not/exist.tar.gz"
    output_dir = os.path.join(tmp_path, "output")
    os.mkdir(output_dir)

    with pytest.raises(FileNotFoundError) as error:
        # Function under test
        grype_wrapper._move_grype_db_archive(missing_output_archive, output_dir)

    # Validate error message
    assert error.value.strerror == ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE
    assert error.value.filename == missing_output_archive


def test_move_grype_db_archive_to_missing_dir(tmp_path, grype_db_archive):
    # Create a var for the output dir, but don't actually create it
    output_dir = os.path.join(tmp_path, "output")

    with pytest.raises(FileNotFoundError) as error:
        # Function under test
        grype_wrapper._move_grype_db_archive(grype_db_archive, output_dir)


def test_open_grype_db_archive(grype_db_archive):
    # Setup expected output vars
    parent_dir = os.path.abspath(os.path.join(grype_db_archive, os.pardir))
    expected_grype_db_file = os.path.join(parent_dir, NEW_VERSION_NAME)

    # Function under test
    latest_grype_db_dir = grype_wrapper._open_grype_db_archive(
        grype_db_archive, parent_dir, NEW_VERSION_NAME
    )

    # Validate expected dir contents and location
    assert os.path.exists(expected_grype_db_file)
    assert latest_grype_db_dir == os.path.join(parent_dir, NEW_VERSION_NAME)
    assert os.path.exists(
        os.path.join(latest_grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)
    )


def test_remove_grype_db_archive(grype_db_archive):
    # Function under test
    grype_wrapper._remove_grype_db_archive(grype_db_archive)

    # Validate
    assert not os.path.exists(grype_db_archive)


def test_init_grype_db_engine(grype_db_dir):
    # Setup output var
    vuln_file_path = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)

    # Function under test
    latest_grype_db_engine = grype_wrapper._init_latest_grype_db_engine(grype_db_dir)

    # Validate expected output
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)


def test_init_grype_db_session(grype_db_dir):
    # Setup db engine
    vuln_file_path = os.path.join(grype_db_dir, grype_wrapper.VULNERABILITY_FILE_NAME)
    db_connect = "sqlite:///{}".format(vuln_file_path)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)

    # Function under test
    latest_grype_db_session = grype_wrapper._init_latest_grype_db_session(
        latest_grype_db_engine
    )

    # Validate output
    assert latest_grype_db_session is not None


def test_init_grype_db(grype_db_parent_dir, grype_db_archive):
    # Setup out vars
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_NAME)
    expected_output_file = os.path.join(
        expected_output_dir, grype_wrapper.VULNERABILITY_FILE_NAME
    )

    # Function under test
    latest_grype_db_dir, latest_grype_db_session = grype_wrapper._init_latest_grype_db(
        grype_db_archive, NEW_VERSION_NAME
    )

    # Validate expected output
    assert os.path.exists(latest_grype_db_dir)
    assert latest_grype_db_dir == expected_output_dir

    assert latest_grype_db_session is not None
    assert os.path.exists(expected_output_file)


def test_remove_local_grype_db(old_grype_db_dir):
    # Function under test
    grype_wrapper._remove_local_grype_db(old_grype_db_dir)

    # Validate output
    assert not os.path.exists(old_grype_db_dir)


def test_init_grype_db_engine(grype_db_parent_dir, old_grype_db_dir, grype_db_archive):
    # Setup
    grype_wrapper._set_grype_db_dir(old_grype_db_dir)
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_NAME)
    expected_output_file = os.path.join(
        expected_output_dir, grype_wrapper.VULNERABILITY_FILE_NAME
    )

    # Function under test
    grype_wrapper.init_grype_db_engine(grype_db_archive, NEW_VERSION_NAME)

    # Validate output
    assert os.path.exists(grype_wrapper._get_grype_db_dir())
    assert grype_wrapper._get_grype_db_dir() == expected_output_dir

    assert grype_wrapper._get_grype_db_session() is not None
    assert os.path.exists(expected_output_file)

    assert not os.path.exists(old_grype_db_dir)


def test_get_current_grype_db_metadata(grype_db_dir):
    # Setup test input
    grype_wrapper._set_grype_db_dir(grype_db_dir)

    # Function under test
    result = grype_wrapper.get_current_grype_db_metadata()

    # Validate result
    assert (
        result["checksum"]
        == "sha256:1db8bd20af545fadc5fb2b25260601d49339349cf04e32650531324ded8a45d0"
    )


def test_get_current_grype_db_metadata_missing_file(tmp_path):
    # Setup test input
    grype_wrapper._set_grype_db_dir(os.path.join(tmp_path))

    # Function under test
    result = grype_wrapper.get_current_grype_db_metadata()

    # Validate result
    assert result is None


def test_get_current_grype_db_metadata_bad_file(tmp_path):
    # Setup test input
    tmp_path.joinpath("metadata.json").touch()
    grype_wrapper._set_grype_db_dir(os.path.join(tmp_path))

    # Function under test
    result = grype_wrapper.get_current_grype_db_metadata()

    # Validate result
    assert result is None


def test_get_proc_env(grype_db_dir):
    # Setup test input
    grype_wrapper._set_grype_db_dir(grype_db_dir)

    # Function under test
    result = grype_wrapper._get_proc_env()

    # Validate result
    assert result["GRYPE_CHECK_FOR_APP_UPDATE"] == "0"
    assert result["GRYPE_LOG_STRUCTURED"] == "1"
    assert result["GRYPE_DB_AUTO_UPDATE"] == "0"
    assert result["GRYPE_DB_CACHE_DIR"] == grype_db_dir


# TODO Replace this with a functional test against the API that calls the function under test.
# This test will not pass on the CI because that machine does not have grype installed.
# I am leaving it for now, but commented out. It is useful for local dev and will
# pass if you have grype installed.
# @pytest.mark.parametrize(
#     "sbom_file_name, expected_output",
#     [("sbom-ubuntu-20.04--pruned.json", "ubuntu")],
# )
# def test_get_vulnerabilities_for_sbom(grype_db_dir, sbom_file_name, expected_output):
#     # Setup test inputs
#     grype_wrapper.grype_db_dir = grype_db_dir
#     test_sbom = get_test_sbom(sbom_file_name).replace("<", "").replace(">", "")
#
#     # Function under test
#     result = grype_wrapper.get_vulnerabilities_for_sbom(test_sbom)
#
#     # Validate results
#     assert result["distro"]["name"] == expected_output


# TODO Replace this with a functional test against the API that calls the function under test.
# This test will not pass on the CI because that machine does not have grype installed.
# I am leaving it for now, but commented out. It is useful for local dev and will
# pass if you have grype installed.
# @pytest.mark.parametrize(
#     "sbom_file_name, expected_output",
#     [("sbom-ubuntu-20.04--pruned.json", "ubuntu")],
# )
# def test_get_vulnerabilities_for_sbom_file(grype_db_dir, sbom_file_name, expected_output):
#     # Setup test inputs
#     grype_wrapper.grype_db_dir = grype_db_dir
#     test_sbom_file = get_test_sbom_file(sbom_file_name)
#
#     # Function under test
#     result = grype_wrapper.get_vulnerabilities_for_sbom_file(test_sbom_file)
#
#     # Validate results
#     assert result["distro"]["name"] == expected_output


@pytest.mark.parametrize(
    "vuln_id, affected_package, namespace, expected_result_length, expected_output",
    [
        ("not_found", None, None, 0, []),
        (None, "not_found", None, 0, []),
        (None, None, "not_found", 0, []),
        (
            None,
            None,
            None,
            10,
            [
                "CVE-2019-16775",
                "CVE-2019-16777",
                "CVE-2019-16776",
                "CVE-2020-10174",
                "CVE-2019-2391",
                "CVE-2020-7610",
                "CVE-2020-8518",
                "CVE-2019-9658",
                "CVE-2019-15690",
                "CVE-2019-20788",
            ],
        ),
        ("CVE-2019-16775", None, None, 1, ["CVE-2019-16775"]),
        (None, "npm", None, 3, ["CVE-2019-16775", "CVE-2019-16777", "CVE-2019-16776"]),
        (
            None,
            None,
            "debian:10",
            10,
            [
                "CVE-2019-16775",
                "CVE-2019-16777",
                "CVE-2019-16776",
                "CVE-2020-10174",
                "CVE-2019-2391",
                "CVE-2020-7610",
                "CVE-2020-8518",
                "CVE-2019-9658",
                "CVE-2019-15690",
                "CVE-2019-20788",
            ],
        ),
        ("CVE-2019-16775", "npm", "debian:10", 1, ["CVE-2019-16775"]),
    ],
)
def test_query_vulnerabilities(
    grype_db_dir,
    vuln_id,
    affected_package,
    namespace,
    expected_result_length,
    expected_output,
):
    # Setup the sqlalchemy artifacts on the test grype db
    test_grype_db_engine = grype_wrapper._init_latest_grype_db_engine(grype_db_dir)
    grype_wrapper._set_grype_db_session(
        grype_wrapper._init_latest_grype_db_session(test_grype_db_engine)
    )

    # Test and validate the query param combinations
    results = grype_wrapper.query_vulnerabilities(
        vuln_id=vuln_id,
        affected_package=affected_package,
        namespace=namespace,
    )
    assert len(results) == expected_result_length
    assert list(map(lambda result: result.id, results)) == expected_output
    # TODO Assert joined vulnerability_metadata is correct
    # I need to further simplify the test data set to keep the expected_output size manageable
    # Or else that matrix is just going to be unreadable
