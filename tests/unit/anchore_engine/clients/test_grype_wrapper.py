import anchore_engine.configuration.localconfig
import json
import os
import pytest
import shutil
import sqlalchemy

from anchore_engine.clients.grype_wrapper import GrypeWrapperSingleton

TEST_DATA_RELATIVE_PATH = "../../data/grype_db/"
GRYPE_ARCHIVE_FILE_NAME = "grype_db_test_archive.tar.gz"
GRYPE_DB_VERSION = "2"

GRYPE_DB_DIR = "grype_db/"
OLD_VERSION_MOCK_CHECKSUM = "old_version"
NEW_VERSION_MOCK_CHECKSUM = "new_version"
VULNERABILITIES = "vulnerabilities"
LAST_SYNCED_TIMESTAMP = "2021-04-07T08:12:05Z"


class TestGrypeWrapperSingleton(GrypeWrapperSingleton):
    @classmethod
    def get_instance(cls):
        """
        Returns a new instance of this class. This method is not intended for use outside of tests.
        """
        cls._grype_wrapper_instance = None
        return TestGrypeWrapperSingleton()


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
    input_dir = os.path.join(parent_dir, NEW_VERSION_MOCK_CHECKSUM)
    shutil.copytree(get_test_file_path(NEW_VERSION_MOCK_CHECKSUM), input_dir)
    return input_dir


@pytest.fixture
def old_grype_db_dir(tmp_path):
    parent_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)
    input_dir = os.path.join(parent_dir, OLD_VERSION_MOCK_CHECKSUM)
    shutil.copytree(get_test_file_path(OLD_VERSION_MOCK_CHECKSUM), input_dir)
    return input_dir


def test_get_missing_grype_db_dir():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    with pytest.raises(ValueError) as error:
        # Function under test
        grype_wrapper_singleton._grype_db_dir

    # Validate error message
    assert str(error.value) is GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


def test_get_missing_grype_db_session():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    with pytest.raises(ValueError) as error:
        # Function under test
        grype_wrapper_singleton._grype_db_session_maker

    # Validate error message
    assert (
        str(error.value)
        is GrypeWrapperSingleton.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE
    )


def test_get_current_grype_db_checksum(grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = grype_db_dir

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_checksum()

    # Validate result
    assert result == NEW_VERSION_MOCK_CHECKSUM


def test_get_current_grype_db_checksum_missing_db_dir_value():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input with a non-existant path
    grype_wrapper_singleton._grype_db_dir = "/does/not/exist"

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_checksum()

    # Validate error message
    assert result is None


def test_get_current_grype_db_checksum_missing_db_dir():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    with pytest.raises(ValueError) as error:
        # Function under test
        result = grype_wrapper_singleton.get_current_grype_db_checksum()

    # Validate error message
    assert str(error.value) == GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


def test_get_default_cache_dir_from_config(grype_db_parent_dir, tmp_path):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    local_db_dir = grype_wrapper_singleton._get_default_grype_db_dir_from_config()

    # Validate the grype db dir exists and is in the correct location
    assert os.path.exists(local_db_dir)
    assert local_db_dir == grype_db_parent_dir


def test_move_grype_db_archive(tmp_path, grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup the output dir to be copied into
    output_dir = os.path.join(tmp_path, "output")
    os.mkdir(output_dir)

    # Function under test
    grype_db_archive_copied_file_location = (
        grype_wrapper_singleton._move_grype_db_archive(grype_db_archive, output_dir)
    )

    # Validate archive was copied and to the correct location
    assert os.path.exists(grype_db_archive_copied_file_location)
    assert grype_db_archive_copied_file_location == os.path.join(
        output_dir, "grype_db_test_archive.tar.gz"
    )


def test_move_missing_grype_db_archive(tmp_path):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup non-existent input archive and real output dir
    missing_output_archive = "/does/not/exist.tar.gz"
    output_dir = os.path.join(tmp_path, "output")
    os.mkdir(output_dir)

    with pytest.raises(FileNotFoundError) as error:
        # Function under test
        grype_wrapper_singleton._move_grype_db_archive(
            missing_output_archive, output_dir
        )

    # Validate error message
    assert (
        error.value.strerror
        == grype_wrapper_singleton.ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE
    )
    assert error.value.filename == missing_output_archive


def test_move_grype_db_archive_to_missing_dir(tmp_path, grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Create a var for the output dir, but don't actually create it
    output_dir = os.path.join(tmp_path, "output")

    with pytest.raises(FileNotFoundError) as error:
        # Function under test
        grype_wrapper_singleton._move_grype_db_archive(grype_db_archive, output_dir)


def test_open_grype_db_archive(grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup input var
    parent_dir = os.path.abspath(os.path.join(grype_db_archive, os.pardir))

    # Setup expected output vars
    expected_output_dir = os.path.join(parent_dir, NEW_VERSION_MOCK_CHECKSUM)
    expected_output_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )

    # Function under test
    latest_grype_db_dir = grype_wrapper_singleton._open_grype_db_archive(
        grype_db_archive, parent_dir, NEW_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
    )

    # Validate expected dir contents and location
    assert os.path.exists(expected_output_dir)
    assert latest_grype_db_dir == expected_output_dir
    assert os.path.exists(os.path.join(expected_output_dir, GRYPE_DB_VERSION))
    assert os.path.exists(
        os.path.join(
            expected_output_dir,
            GRYPE_DB_VERSION,
            grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
        )
    )


def test_store_grype_db_version_to_file(grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup input var and create directories
    parent_dir = os.path.abspath(os.path.join(grype_db_archive, os.pardir))
    latest_grype_db_dir = os.path.join(parent_dir, NEW_VERSION_MOCK_CHECKSUM)
    versioned_dir = os.path.join(latest_grype_db_dir, GRYPE_DB_VERSION)
    if not os.path.exists(versioned_dir):
        os.makedirs(versioned_dir)

    # Setup expected output vars
    expected_output_file = os.path.join(
        versioned_dir, grype_wrapper_singleton.ENGINE_METADATA_FILE_NAME
    )
    expected_engine_metadata = {
        "archive_checksum": NEW_VERSION_MOCK_CHECKSUM,
        "grype_db_version": GRYPE_DB_VERSION,
    }

    # Function under test
    grype_wrapper_singleton._write_engine_metadata_to_file(
        latest_grype_db_dir, NEW_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
    )

    # Validate output
    assert os.path.exists(os.path.join(expected_output_file))

    # Validate the contents of the engine_metadata file
    with open(expected_output_file, "r") as read_file:
        engine_metadata = json.load(read_file)

    assert engine_metadata == expected_engine_metadata


def test_remove_grype_db_archive(grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    grype_wrapper_singleton._remove_grype_db_archive(grype_db_archive)

    # Validate
    assert not os.path.exists(grype_db_archive)


def test_init_grype_db_engine(grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup output var
    vuln_file_path = os.path.join(
        grype_db_dir, grype_wrapper_singleton.VULNERABILITY_FILE_NAME
    )

    # Function under test
    latest_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        grype_db_dir
    )

    # Validate expected output
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)


def test_init_grype_db_session(grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup db engine
    vuln_file_path = os.path.join(
        grype_db_dir, grype_wrapper_singleton.VULNERABILITY_FILE_NAME
    )
    db_connect = "sqlite:///{}".format(vuln_file_path)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(vuln_file_path)

    # Function under test
    latest_grype_db_session = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            latest_grype_db_engine
        )
    )

    # Validate output
    assert latest_grype_db_session is not None


def test_init_grype_db(grype_db_parent_dir, grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup expected output vars
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_MOCK_CHECKSUM)
    expected_output_vulnerability_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )
    expected_output_metadata_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.METADATA_FILE_NAME,
    )
    expected_output_engine_metadata_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.ENGINE_METADATA_FILE_NAME,
    )

    # Function under test
    (
        latest_grype_db_dir,
        latest_grype_db_session,
    ) = grype_wrapper_singleton._init_latest_grype_db(
        grype_db_archive, NEW_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
    )

    # Validate expected output
    assert os.path.exists(latest_grype_db_dir)
    assert latest_grype_db_dir == expected_output_dir

    assert latest_grype_db_session is not None
    assert os.path.exists(expected_output_vulnerability_file)
    assert os.path.exists(expected_output_metadata_file)
    assert os.path.exists(expected_output_engine_metadata_file)


def test_remove_local_grype_db(old_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    grype_wrapper_singleton._remove_local_grype_db(old_grype_db_dir)

    # Validate output
    assert not os.path.exists(old_grype_db_dir)


def test_init_grype_db_engine(grype_db_parent_dir, old_grype_db_dir, grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup
    grype_wrapper_singleton._grype_db_dir = old_grype_db_dir
    expected_output_dir = os.path.join(grype_db_parent_dir, NEW_VERSION_MOCK_CHECKSUM)
    expected_output_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        GrypeWrapperSingleton.VULNERABILITY_FILE_NAME,
    )

    # Function under test
    grype_wrapper_singleton.init_grype_db_engine(
        grype_db_archive, NEW_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
    )

    # Validate output
    assert os.path.exists(grype_wrapper_singleton._grype_db_dir)
    assert grype_wrapper_singleton._grype_db_dir == expected_output_dir

    assert grype_wrapper_singleton._grype_db_session_maker is not None
    assert os.path.exists(expected_output_file)

    assert not os.path.exists(old_grype_db_dir)


def test_get_current_grype_db_metadata(grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = grype_db_dir

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_metadata()

    # Validate result
    assert (
        result["checksum"]
        == "sha256:1db8bd20af545fadc5fb2b25260601d49339349cf04e32650531324ded8a45d0"
    )


def test_get_current_grype_db_metadata_missing_dir():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    with pytest.raises(ValueError) as error:
        grype_wrapper_singleton.get_current_grype_db_metadata()

    # Validate error message
    assert str(error.value) == GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


def test_get_current_grype_db_metadata_missing_file(tmp_path):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = os.path.join(tmp_path)

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_metadata()

    # Validate result
    assert result is None


def test_get_current_grype_db_metadata_bad_file(tmp_path):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    tmp_path.joinpath("metadata.json").touch()
    grype_wrapper_singleton._grype_db_dir = os.path.join(tmp_path)

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_metadata()

    # Validate result
    assert result is None


def test_get_proc_env(grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = grype_db_dir

    # Function under test
    result = grype_wrapper_singleton._get_proc_env()

    # Validate result
    assert result["GRYPE_CHECK_FOR_APP_UPDATE"] == "0"
    assert result["GRYPE_LOG_STRUCTURED"] == "1"
    assert result["GRYPE_DB_AUTO_UPDATE"] == "0"
    assert result["GRYPE_DB_CACHE_DIR"] == grype_db_dir


def test_get_proc_env_missing_dir():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    with pytest.raises(ValueError) as error:
        grype_wrapper_singleton._get_proc_env()

    # Validate error message
    assert str(error.value) == GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


# This test will not pass on the CI because that machine does not have grype installed.
# I am leaving it for now, but commented out. It is useful for local dev and will
# pass if you have grype installed.
# def test_get_grype_version():
#     # Create grype_wrapper_singleton instance
#     grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
#
#     # Function under test
#     result = grype_wrapper_singleton.get_grype_version()
#
#     # Validate results
#     assert result["application"] == "grype"
#     assert result["version"] is not None


# TODO Replace this with a functional test against the API that calls the function under test.
# This test will not pass on the CI because that machine does not have grype installed.
# I am leaving it for now, but commented out. It is useful for local dev and will
# pass if you have grype installed.
# @pytest.mark.parametrize(
#     "sbom_file_name, expected_output",
#     [("sbom-ubuntu-20.04--pruned.json", "ubuntu")],
# )
# def test_get_vulnerabilities_for_sbom(grype_db_dir, sbom_file_name, expected_output):
#     # Create grype_wrapper_singleton instance
#     grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
#
#     # Setup test inputs
#     grype_wrapper_singleton._grype_db_dir = grype_db_dir
#     test_sbom = get_test_sbom(sbom_file_name).replace("<", "").replace(">", "")
#
#     # Function under test
#     result = grype_wrapper_singleton.get_vulnerabilities_for_sbom(test_sbom)
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
# def test_get_vulnerabilities_for_sbom_file(
#     grype_db_dir, sbom_file_name, expected_output
# ):
#     # Create grype_wrapper_singleton instance
#     grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
#
#     # Setup test inputs
#     grype_wrapper_singleton._grype_db_dir = grype_db_dir
#     test_sbom_file = get_test_sbom_file(sbom_file_name)
#
#     # Function under test
#     result = grype_wrapper_singleton.get_vulnerabilities_for_sbom_file(test_sbom_file)
#
#     # Validate results
#     assert result["distro"]["name"] == expected_output


def test_get_vulnerabilities_for_sbom_missing_session():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    with pytest.raises(ValueError) as error:
        grype_wrapper_singleton.get_vulnerabilities_for_sbom(None)

    # Validate error message
    assert str(error.value) == GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


def test_get_vulnerabilities_for_sbom_file_missing_session():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    with pytest.raises(ValueError) as error:
        grype_wrapper_singleton.get_vulnerabilities_for_sbom_file(None)

    # Validate error message
    assert str(error.value) == GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE


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
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup the sqlalchemy artifacts on the test grype db
    test_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        grype_db_dir
    )
    grype_wrapper_singleton._grype_db_session_maker = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            test_grype_db_engine
        )
    )

    # Test and validate the query param combinations
    results = grype_wrapper_singleton.query_vulnerabilities(
        vuln_id=vuln_id,
        affected_package=affected_package,
        namespace=namespace,
    )
    assert len(results) == expected_result_length
    assert list(map(lambda result: result.id, results)) == expected_output
    # TODO Assert joined vulnerability_metadata is correct
    # I need to further simplify the test data set to keep the expected_output size manageable
    # Or else that matrix is just going to be unreadable


def test_query_vulnerabilities_missing_session():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    with pytest.raises(ValueError) as error:
        grype_wrapper_singleton.query_vulnerabilities(
            vuln_id=None,
            affected_package=None,
            namespace=None,
        )

    # Validate error message
    assert (
        str(error.value)
        == GrypeWrapperSingleton.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE
    )


@pytest.mark.parametrize(
    "expected_group, expected_count",
    [
        ("debian:10", 4),
        ("alpine:3.10", 3),
        ("github:python", 3),
    ],
)
def test_query_record_source_counts(grype_db_dir, expected_group, expected_count):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup the grype_db_dir state and the sqlalchemy artifacts on the test grype db
    grype_wrapper_singleton._grype_db_dir = grype_db_dir
    test_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        grype_db_dir
    )

    grype_wrapper_singleton._grype_db_session_maker = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            test_grype_db_engine
        )
    )

    # Function under test
    results = grype_wrapper_singleton.query_record_source_counts()

    # Validate output
    filtered_result = next(
        (result for result in results if result.group == expected_group), None
    )
    assert filtered_result is not None
    assert filtered_result.feed == VULNERABILITIES
    assert filtered_result.count == expected_count
    assert filtered_result.last_synced == LAST_SYNCED_TIMESTAMP
