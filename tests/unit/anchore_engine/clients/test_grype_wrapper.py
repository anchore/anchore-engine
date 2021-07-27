import json
import os
import shutil
from queue import Empty, Queue
from threading import Thread

import pytest
import sqlalchemy
from sqlalchemy.orm import sessionmaker

import anchore_engine.configuration.localconfig
from anchore_engine.clients.grype_wrapper import (
    VULNERABILITIES,
    GrypeDBEngineMetadata,
    GrypeDBMetadata,
    GrypeWrapperSingleton,
)

TEST_DATA_RELATIVE_PATH = "../../data/grype_db/"
GRYPE_ARCHIVE_FILE_NAME = "grype_db_test_archive.tar.gz"
GRYPE_DB_VERSION = "3"

GRYPE_DB_DIR = "grype_db/"
PRODUCTION_VERSION_MOCK_CHECKSUM = "old_version"
STAGED_VERSION_MOCK_CHECKSUM = "new_version"
MOCK_DB_CHECKSUM = "mock_db_checksum"
MOCK_BUILT_TIMESTAMP = "2021-04-07T08:12:05Z"
LAST_SYNCED_TIMESTAMP = "2021-04-07T08:12:05Z"


class TestGrypeWrapperSingleton(GrypeWrapperSingleton):
    @classmethod
    def get_instance(cls):
        """
        Returns a new test instance of this class. This method is not intended for use outside of tests.
        """
        cls._grype_wrapper_instance = None
        return TestGrypeWrapperSingleton()


def get_test_file_path(basename: str) -> str:
    """
    Get the base dir for grype_db test files in the repo
    """
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TEST_DATA_RELATIVE_PATH, basename
    )


def get_test_sbom(sbom_file_name) -> str:
    """
    Parameterized helper function to get the contents of a test sbom file
    """
    full_sbom_path = get_test_file_path(sbom_file_name)
    with open(full_sbom_path, "r") as read_file:
        return read_file.read().replace("\n", "")


def get_test_sbom_file(sbom_file_name) -> str:
    """
    Parameterized helper function to get the path to a test sbom file
    """
    full_sbom_path = get_test_file_path(sbom_file_name)
    return full_sbom_path


def mock_synced_dir(base_path, mock_checksum, include_engine_metadata) -> str:
    """
    Mocks a grype_db dir, with an optional to engine metadata file, with test files from the repo.
    Returns the path to the grype_db dir
    """
    # Get the base dir to copy test data from
    test_dir = get_test_file_path(mock_checksum)

    # Create the base dir to copy test data to
    parent_dir = os.path.join(base_path, "input")
    if not os.path.exists(parent_dir):
        os.mkdir(parent_dir)

    # Create the subdirs we will copy data into and pas to grype wrapper methods in our tests
    grype_dir = os.path.join(parent_dir, mock_checksum)
    versioned_dir = os.path.join(grype_dir, GRYPE_DB_VERSION)
    if not os.path.exists(versioned_dir):
        os.makedirs(versioned_dir)

    # Copy test files
    shutil.copy(
        os.path.join(test_dir, GrypeWrapperSingleton.VULNERABILITY_FILE_NAME),
        versioned_dir,
    )
    shutil.copy(
        os.path.join(test_dir, GrypeWrapperSingleton.METADATA_FILE_NAME), versioned_dir
    )
    # Since grype wrapper creates the engine metadata, not all tests require it to be mocked
    if include_engine_metadata:
        shutil.copy(
            os.path.join(test_dir, GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME),
            versioned_dir,
        )

    # Return the grype_db_dir
    return grype_dir


@pytest.fixture
def grype_db_parent_dir(tmp_path):
    """
    Mocks the parent dir from config for storing the grype_db.
    """
    localconfig = anchore_engine.configuration.localconfig.get_config()
    localconfig["service_dir"] = tmp_path
    anchore_engine.configuration.localconfig.localconfig = localconfig

    return os.path.join(tmp_path, GRYPE_DB_DIR)


@pytest.fixture
def grype_db_archive(tmp_path):
    """
    Mocks a grype_db archive file in a tmp director to be staged by the grype wrapper.
    Returns the path to the archive file.
    """
    input_dir = os.path.join(tmp_path, "input")
    if not os.path.exists(input_dir):
        os.mkdir(input_dir)
    shutil.copy(get_test_file_path(GRYPE_ARCHIVE_FILE_NAME), input_dir)
    return os.path.join(input_dir, "grype_db_test_archive.tar.gz")


@pytest.fixture
def staging_grype_db_dir(tmp_path):
    """
    Mocks a grype_db dir, meant to represent a staging grype_db instance.
    This dir includes the engine metadata file
    Returns the path to the grype_db dir
    """
    return mock_synced_dir(tmp_path, STAGED_VERSION_MOCK_CHECKSUM, True)


@pytest.fixture
def production_grype_db_dir(tmp_path):
    """
    Mocks a grype_db dir, meant to represent a production grype_db instance.
    This dir includes the engine metadata file
    Returns the path to the grype_db dir
    """
    return mock_synced_dir(tmp_path, PRODUCTION_VERSION_MOCK_CHECKSUM, True)


@pytest.fixture
def staging_grype_db_dir_no_engine_metadata(tmp_path):
    """
    Mocks a grype_db dir, meant to represent a staging grype_db instance.
    This dir does not include the engine metadata file
    Returns the path to the grype_db dir
    """
    return mock_synced_dir(tmp_path, STAGED_VERSION_MOCK_CHECKSUM, False)


@pytest.fixture
def production_grype_db_dir_no_engine_metadata(tmp_path):
    """
    Mocks a grype_db dir, meant to represent a production grype_db instance.
    This dir does not include the engine metadata file
    Returns the path to the grype_db dir
    """
    return mock_synced_dir(tmp_path, PRODUCTION_VERSION_MOCK_CHECKSUM, False)


@pytest.fixture
def mock_grype_db_session_maker():
    """
    Returns an instantiated (but not functional) sqlalchemy sessionmake object for use in tests.
    This object can be used in tests and parameterized to test methods that require it, but cannot
    actually be successfully queried for data because it is not backed by a real database file.
    """
    db_connect = GrypeWrapperSingleton.SQL_LITE_URL_TEMPLATE.format("/does/not/exist")
    mock_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    return sessionmaker(bind=mock_grype_db_engine)


def test_get_missing_grype_db_dir():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError, match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE
    ):
        # Function under test
        grype_wrapper_singleton._grype_db_dir


def test_get_missing_grype_db_session():
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton._grype_db_session_maker


def test_get_current_grype_db_checksum(staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = staging_grype_db_dir

    # Function under test
    result = grype_wrapper_singleton.get_current_grype_db_checksum()

    # Validate result
    assert result == STAGED_VERSION_MOCK_CHECKSUM


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

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton.get_current_grype_db_checksum()


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

    # Expect exception and validate message
    with pytest.raises(
        FileNotFoundError,
        match=grype_wrapper_singleton.ARCHIVE_FILE_NOT_FOUND_ERROR_MESSAGE,
    ) as error:
        # Function under test
        grype_wrapper_singleton._move_grype_db_archive(
            missing_output_archive, output_dir
        )

    # Validate error value
    assert error.value.filename == missing_output_archive


def test_move_grype_db_archive_to_missing_dir(tmp_path, grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Create a var for the output dir, but don't actually create it
    output_dir = os.path.join(tmp_path, "output")

    # Expect exception
    with pytest.raises(FileNotFoundError) as error:
        # Function under test
        grype_wrapper_singleton._move_grype_db_archive(grype_db_archive, output_dir)


def test_open_grype_db_archive(grype_db_archive):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup input var
    parent_dir = os.path.abspath(os.path.join(grype_db_archive, os.pardir))

    # Setup expected output vars
    expected_output_dir = os.path.join(parent_dir, STAGED_VERSION_MOCK_CHECKSUM)
    expected_output_file = os.path.join(
        expected_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )

    # Function under test
    latest_grype_db_dir = grype_wrapper_singleton._open_grype_db_archive(
        grype_db_archive, parent_dir, STAGED_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
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


def test_write_engine_metadata_to_file(staging_grype_db_dir_no_engine_metadata):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup input var and create directories
    versioned_dir = os.path.join(
        staging_grype_db_dir_no_engine_metadata, GRYPE_DB_VERSION
    )
    if not os.path.exists(versioned_dir):
        os.makedirs(versioned_dir)

    # Setup expected output vars
    expected_output_file = os.path.join(
        versioned_dir, grype_wrapper_singleton.ENGINE_METADATA_FILE_NAME
    )
    expected_engine_metadata = {
        "archive_checksum": STAGED_VERSION_MOCK_CHECKSUM,
        "grype_db_version": GRYPE_DB_VERSION,
        "db_checksum": MOCK_DB_CHECKSUM,
    }

    # Function under test
    grype_wrapper_singleton._write_engine_metadata_to_file(
        staging_grype_db_dir_no_engine_metadata,
        STAGED_VERSION_MOCK_CHECKSUM,
        GRYPE_DB_VERSION,
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


def test_init_grype_db_engine(staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup expected output var
    expected_output_path = os.path.join(
        staging_grype_db_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )

    # Function under test
    latest_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        staging_grype_db_dir, GRYPE_DB_VERSION
    )

    # Validate expected output
    assert str(
        latest_grype_db_engine.url
    ) == GrypeWrapperSingleton.SQL_LITE_URL_TEMPLATE.format(expected_output_path)


def test_init_latest_grype_db_engine(staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup expected output var
    expected_output = os.path.join(
        staging_grype_db_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )

    # Function under test
    latest_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        staging_grype_db_dir,
        GRYPE_DB_VERSION,
    )

    # Validate output
    assert str(latest_grype_db_engine.url) == "sqlite:///{}".format(expected_output)


def test_init_latest_grype_db_session_maker(staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup db engine
    vuln_file_path = os.path.join(
        staging_grype_db_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )
    db_connect = GrypeWrapperSingleton.SQL_LITE_URL_TEMPLATE.format(vuln_file_path)
    latest_grype_db_engine = sqlalchemy.create_engine(db_connect, echo=True)
    assert str(
        latest_grype_db_engine.url
    ) == GrypeWrapperSingleton.SQL_LITE_URL_TEMPLATE.format(vuln_file_path)

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
    expected_output_dir = os.path.join(
        grype_db_parent_dir, STAGED_VERSION_MOCK_CHECKSUM
    )
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
        latest_grype_db_session_maker,
    ) = grype_wrapper_singleton._init_latest_grype_db(
        grype_db_archive, STAGED_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION
    )

    # Validate expected output
    assert os.path.exists(latest_grype_db_dir)
    assert latest_grype_db_dir == expected_output_dir

    assert latest_grype_db_session_maker is not None
    assert os.path.exists(expected_output_vulnerability_file)
    assert os.path.exists(expected_output_metadata_file)
    assert os.path.exists(expected_output_engine_metadata_file)


def test_remove_local_grype_db(production_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Function under test
    grype_wrapper_singleton._remove_local_grype_db(production_grype_db_dir)

    # Validate output
    assert not os.path.exists(production_grype_db_dir)


def test_update_grype_db_staging(
    grype_db_parent_dir,
    staging_grype_db_dir,
    mock_grype_db_session_maker,
    grype_db_archive,
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup expected output vars
    expected_staging_output_dir = os.path.join(
        grype_db_parent_dir, STAGED_VERSION_MOCK_CHECKSUM
    )
    expected_staging_output_vulnerability_file = os.path.join(
        expected_staging_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )
    expected_staging_output_metadata_file = os.path.join(
        expected_staging_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.METADATA_FILE_NAME,
    )
    expected_staging_output_engine_metadata_file = os.path.join(
        expected_staging_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.ENGINE_METADATA_FILE_NAME,
    )

    # Function under test
    grype_wrapper_singleton.update_grype_db(
        grype_db_archive, STAGED_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION, True
    )

    # Validate output
    # First assert the production grype_db vars are unchanged
    # Since they were not set this means they should be None
    assert grype_wrapper_singleton._grype_db_dir_internal is None
    assert grype_wrapper_singleton._grype_db_session_maker_internal is None

    # Next assert the staging grype_db exists
    assert grype_wrapper_singleton._staging_grype_db_dir == expected_staging_output_dir

    # Assert the staging dirs and files were created
    assert os.path.exists(grype_wrapper_singleton._staging_grype_db_dir)
    assert os.path.exists(expected_staging_output_vulnerability_file)
    assert os.path.exists(expected_staging_output_metadata_file)
    assert os.path.exists(expected_staging_output_engine_metadata_file)

    # Finally assert the staging session maker exists
    assert grype_wrapper_singleton._staging_grype_db_session_maker is not None


def test_update_grype_db_production(
    grype_db_parent_dir,
    production_grype_db_dir,
    mock_grype_db_session_maker,
    grype_db_archive,
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup expected output vars
    expected_production_output_dir = os.path.join(
        grype_db_parent_dir, PRODUCTION_VERSION_MOCK_CHECKSUM
    )
    expected_production_output_vulnerability_file = os.path.join(
        expected_production_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.VULNERABILITY_FILE_NAME,
    )
    expected_production_output_metadata_file = os.path.join(
        expected_production_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.METADATA_FILE_NAME,
    )
    expected_production_output_engine_metadata_file = os.path.join(
        expected_production_output_dir,
        GRYPE_DB_VERSION,
        grype_wrapper_singleton.ENGINE_METADATA_FILE_NAME,
    )

    # Function under test
    grype_wrapper_singleton.update_grype_db(
        grype_db_archive, PRODUCTION_VERSION_MOCK_CHECKSUM, GRYPE_DB_VERSION, False
    )

    # Validate output
    # First assert the staging grype_db vars are unchanged
    # Since they were not set this means they should be None
    assert grype_wrapper_singleton._staging_grype_db_dir_internal is None
    assert grype_wrapper_singleton._staging_grype_db_session_maker_internal is None

    # Next assert the production grype_db exists
    assert grype_wrapper_singleton._grype_db_dir == expected_production_output_dir

    # Assert the production dirs and files were created
    assert os.path.exists(grype_wrapper_singleton._grype_db_dir)
    assert os.path.exists(expected_production_output_vulnerability_file)
    assert os.path.exists(expected_production_output_metadata_file)
    assert os.path.exists(expected_production_output_engine_metadata_file)

    # Finally assert the production session maker exists
    assert grype_wrapper_singleton._grype_db_session_maker is not None


def test_unstage_grype_db(
    production_grype_db_dir_no_engine_metadata, staging_grype_db_dir_no_engine_metadata
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test inputs
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir_no_engine_metadata
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION
    grype_wrapper_singleton._grype_db_session_maker = mock_grype_db_session_maker
    grype_wrapper_singleton._staging_grype_db_dir = (
        staging_grype_db_dir_no_engine_metadata
    )
    grype_wrapper_singleton._staging_grype_db_version = GRYPE_DB_VERSION
    grype_wrapper_singleton._staging_grype_db_session_maker = (
        mock_grype_db_session_maker
    )

    grype_wrapper_singleton._write_engine_metadata_to_file(
        production_grype_db_dir_no_engine_metadata,
        PRODUCTION_VERSION_MOCK_CHECKSUM,
        GRYPE_DB_VERSION,
    )

    grype_wrapper_singleton._write_engine_metadata_to_file(
        staging_grype_db_dir_no_engine_metadata,
        STAGED_VERSION_MOCK_CHECKSUM,
        GRYPE_DB_VERSION,
    )

    expected_metadata = GrypeDBEngineMetadata(
        db_checksum=MOCK_DB_CHECKSUM,
        archive_checksum=PRODUCTION_VERSION_MOCK_CHECKSUM,
        grype_db_version=GRYPE_DB_VERSION,
    )

    # Method under test
    result = grype_wrapper_singleton.unstage_grype_db()

    # Validate response
    assert result == expected_metadata

    # Validate grype wrapper state
    # Production vars remain unchanged
    assert (
        grype_wrapper_singleton._grype_db_dir
        == production_grype_db_dir_no_engine_metadata
    )
    assert grype_wrapper_singleton._grype_db_version == GRYPE_DB_VERSION
    assert (
        grype_wrapper_singleton._grype_db_session_maker == mock_grype_db_session_maker
    )
    # Staging vars are now all None
    assert grype_wrapper_singleton._staging_grype_db_dir is None
    assert grype_wrapper_singleton._staging_grype_db_version is None
    assert grype_wrapper_singleton._staging_grype_db_session_maker is None


def test_convert_grype_db_metadata(production_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test inputs
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    # Setup expected output
    expected_output = GrypeDBMetadata(
        built=MOCK_BUILT_TIMESTAMP,
        version=int(GRYPE_DB_VERSION),
        checksum=MOCK_DB_CHECKSUM,
    )

    # Function under test
    result = grype_wrapper_singleton.get_grype_db_metadata()

    assert result == expected_output


def test_convert_grype_db_engine_metadata(production_grype_db_dir_no_engine_metadata):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test inputs
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir_no_engine_metadata
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION
    grype_wrapper_singleton._write_engine_metadata_to_file(
        production_grype_db_dir_no_engine_metadata,
        STAGED_VERSION_MOCK_CHECKSUM,
        GRYPE_DB_VERSION,
    )

    # Setup expected output
    expected_output = GrypeDBEngineMetadata(
        db_checksum=MOCK_DB_CHECKSUM,
        archive_checksum=STAGED_VERSION_MOCK_CHECKSUM,
        grype_db_version=GRYPE_DB_VERSION,
    )

    # Function under test
    result = grype_wrapper_singleton.get_grype_db_engine_metadata()

    assert result == expected_output


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_staging_grype_db_metadata(
    production_grype_db_dir, staging_grype_db_dir, metadata_file_name
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test inputs
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION
    grype_wrapper_singleton._staging_grype_db_dir = staging_grype_db_dir
    grype_wrapper_singleton._staging_grype_db_version = GRYPE_DB_VERSION

    # Setup expected output
    metadata_file_path = os.path.join(
        production_grype_db_dir, GRYPE_DB_VERSION, metadata_file_name
    )
    with open(metadata_file_path, "r") as read_file:
        expected_metadata = json.load(read_file)

    # Function under test
    result = grype_wrapper_singleton._get_metadata_file_contents(
        metadata_file_name, use_staging=False
    )

    # Validate result
    assert result == expected_metadata


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_current_grype_db_metadata(
    production_grype_db_dir, staging_grype_db_dir, metadata_file_name
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test inputs
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION
    grype_wrapper_singleton._staging_grype_db_dir = staging_grype_db_dir
    grype_wrapper_singleton._staging_grype_db_version = GRYPE_DB_VERSION

    # Setup expected output
    metadata_file_path = os.path.join(
        staging_grype_db_dir, GRYPE_DB_VERSION, metadata_file_name
    )
    with open(metadata_file_path, "r") as read_file:
        expected_metadata = json.load(read_file)

    # Function under test
    result = grype_wrapper_singleton._get_metadata_file_contents(
        metadata_file_name, use_staging=True
    )

    # Validate result
    assert result == expected_metadata


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_grype_db_metadata_missing_dir(metadata_file_name):
    # Create grype_wrapper_singleton instance, with grype_db_version but no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton._get_metadata_file_contents(metadata_file_name)


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_grype_db_metadata_missing_version(metadata_file_name):
    # Create grype_wrapper_singleton instance, with grype_db_dir but no grype_db_version set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
    grype_wrapper_singleton._grype_db_dir = "dummy_version"

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_VERSION_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton._get_metadata_file_contents(metadata_file_name)


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_current_grype_db_metadata_missing_file(tmp_path, metadata_file_name):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = os.path.join(tmp_path)
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    # Function under test
    result = grype_wrapper_singleton._get_metadata_file_contents(metadata_file_name)

    # Validate result
    assert result is None


@pytest.mark.parametrize(
    "metadata_file_name",
    [
        GrypeWrapperSingleton.METADATA_FILE_NAME,
        GrypeWrapperSingleton.ENGINE_METADATA_FILE_NAME,
    ],
)
def test_get_current_grype_db_metadata_bad_file(tmp_path, metadata_file_name):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    tmp_path.joinpath("metadata.json").touch()
    grype_wrapper_singleton._grype_db_dir = os.path.join(tmp_path)
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    # Function under test
    result = grype_wrapper_singleton._get_metadata_file_contents(metadata_file_name)

    # Validate result
    assert result is None


def test_get_staging_proc_env(production_grype_db_dir, staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._staging_grype_db_dir = staging_grype_db_dir

    # Function under test
    result = grype_wrapper_singleton._get_env_variables(use_staging=True)

    # Validate result
    assert result["GRYPE_CHECK_FOR_APP_UPDATE"] == "0"
    assert result["GRYPE_LOG_STRUCTURED"] == "1"
    assert result["GRYPE_DB_AUTO_UPDATE"] == "0"
    assert result["GRYPE_DB_CACHE_DIR"] == staging_grype_db_dir


def test_get_production_proc_env(production_grype_db_dir, staging_grype_db_dir):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup test input
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._staging_grype_db_dir = staging_grype_db_dir

    # Function under test
    result = grype_wrapper_singleton._get_env_variables()

    # Validate result
    assert result["GRYPE_CHECK_FOR_APP_UPDATE"] == "0"
    assert result["GRYPE_LOG_STRUCTURED"] == "1"
    assert result["GRYPE_DB_AUTO_UPDATE"] == "0"
    assert result["GRYPE_DB_CACHE_DIR"] == production_grype_db_dir


def test_get_proc_env_missing_dir():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton._get_env_variables()


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
#     [
#         ("sbom-ubuntu-20.04--pruned.json", "ubuntu"),
#         ("sbom-alpine-3.2.0.json", "alpine"),
#     ],
# )
# def test_get_vulnerabilities_for_sbom(grype_db_dir, sbom_file_name, expected_output):
#     # Create grype_wrapper_singleton instance
#     grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
#
#     # Setup test inputs
#     grype_wrapper_singleton._grype_db_dir = grype_db_dir
#     test_sbom = get_test_sbom(sbom_file_name)
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
#     [
#         ("sbom-ubuntu-20.04--pruned.json", "ubuntu"),
#         ("sbom-alpine-3.2.0.json", "alpine"),
#     ],
# )
# def test_get_vulnerabilities_for_sbom_file(
#     staging_grype_db_dir, sbom_file_name, expected_output
# ):
#     # Create grype_wrapper_singleton instance
#     grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()
#
#     # Setup test inputs
#     grype_wrapper_singleton._grype_db_dir = staging_grype_db_dir
#     test_sbom_file = get_test_sbom_file(sbom_file_name)
#
#     # Function under test
#     result = grype_wrapper_singleton.get_vulnerabilities_for_sbom_file(test_sbom_file)
#
#     # Validate results
#     assert result["distro"]["name"] == expected_output


def test_get_vulnerabilities_for_sbom_missing_dir():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton.get_vulnerabilities_for_sbom(None)


def test_get_vulnerabilities_for_sbom_file_missing_dir():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_DIR_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton.get_vulnerabilities_for_sbom_file(None)


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
            20,
            [
                "CVE-2019-15690",
                "CVE-2019-16775",
                "CVE-2019-16776",
                "CVE-2019-16777",
                "CVE-2019-20788",
                "CVE-2019-2391",
                "CVE-2019-9658",
                "CVE-2020-10174",
                "CVE-2020-7610",
                "CVE-2020-8518",
            ],
        ),
        ("CVE-2019-16775", None, None, 1, ["CVE-2019-16775"]),
        (None, "npm", None, 3, ["CVE-2019-16775", "CVE-2019-16776", "CVE-2019-16777"]),
        (
            None,
            None,
            "debian:10",
            4,
            [
                "CVE-2019-16775",
                "CVE-2019-16776",
                "CVE-2019-16777",
                "CVE-2020-10174",
            ],
        ),
        ("CVE-2019-16775", None, None, 1, ["CVE-2019-16775"]),
        (None, "npm", None, 3, ["CVE-2019-16775", "CVE-2019-16776", "CVE-2019-16777"]),
        (
            None,
            None,
            "debian:10",
            4,
            ["CVE-2019-16775", "CVE-2019-16776", "CVE-2019-16777", "CVE-2020-10174"],
        ),
        ("CVE-2019-16775", "npm", "debian:10", 1, ["CVE-2019-16775"]),
    ],
)
def test_query_vulnerabilities(
    production_grype_db_dir,
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
        production_grype_db_dir, GRYPE_DB_VERSION
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

    # Validate results
    assert len(results) == expected_result_length
    assert (
        sorted(
            list(set(map(lambda result: result.GrypeVulnerabilityMetadata.id, results)))
        )
        == expected_output
    )


def test_query_vulnerabilities_missing_session():
    # Create grype_wrapper_singleton instance, with no grype_db_dir set
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Expect exception and validate message
    with pytest.raises(
        ValueError,
        match=GrypeWrapperSingleton.MISSING_GRYPE_DB_SESSION_MAKER_ERROR_MESSAGE,
    ):
        # Function under test
        grype_wrapper_singleton.query_vulnerabilities(
            vuln_id=None,
            affected_package=None,
            namespace=None,
        )


@pytest.mark.parametrize(
    "expected_group, expected_count, use_staging",
    [
        ("debian:10", 3, True),
        ("alpine:3.10", 2, True),
        ("github:python", 2, True),
        ("debian:10", 4, False),
        ("alpine:3.10", 3, False),
        ("github:python", 3, False),
    ],
)
def test_query_record_source_counts(
    staging_grype_db_dir,
    production_grype_db_dir,
    expected_group,
    expected_count,
    use_staging,
):
    # Create grype_wrapper_singleton instance
    grype_wrapper_singleton = TestGrypeWrapperSingleton.get_instance()

    # Setup the grype_db_dir state and the sqlalchemy artifacts on the test staging grype db
    grype_wrapper_singleton._staging_grype_db_dir = staging_grype_db_dir
    grype_wrapper_singleton._staging_grype_db_version = GRYPE_DB_VERSION

    test_staging_grype_db_engine = grype_wrapper_singleton._init_latest_grype_db_engine(
        staging_grype_db_dir, GRYPE_DB_VERSION
    )

    grype_wrapper_singleton._staging_grype_db_session_maker = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            test_staging_grype_db_engine
        )
    )

    # Setup the grype_db_dir state and the sqlalchemy artifacts on the test production grype db
    grype_wrapper_singleton._grype_db_dir = production_grype_db_dir
    grype_wrapper_singleton._grype_db_version = GRYPE_DB_VERSION

    test_production_grype_db_engine = (
        grype_wrapper_singleton._init_latest_grype_db_engine(
            production_grype_db_dir, GRYPE_DB_VERSION
        )
    )

    grype_wrapper_singleton._grype_db_session_maker = (
        grype_wrapper_singleton._init_latest_grype_db_session_maker(
            test_production_grype_db_engine
        )
    )

    # Function under test
    results = grype_wrapper_singleton.query_record_source_counts(
        use_staging=use_staging
    )

    # Validate output
    filtered_result = next(
        (result for result in results if result.group == expected_group), None
    )
    assert filtered_result is not None
    assert filtered_result.feed == VULNERABILITIES
    assert filtered_result.count == expected_count
    assert filtered_result.last_synced == LAST_SYNCED_TIMESTAMP


class TestLocking:
    @staticmethod
    def hold_read_lock(grype_wrapper, name, input_queue, output_queue):
        """
        Acquire and hold a read lock until instructed to release it.
        """
        print("Waiting to acquire read lock for {}".format(name))
        with grype_wrapper.read_lock_access() as acquired:
            output_queue.put(name)
            print("Read lock acquired for {} - {}".format(name, acquired))
            if input_queue.get(block=True):
                print("Releasing read lock for {}".format(name))
                return

    @staticmethod
    def hold_write_lock(grype_wrapper, name, input_queue, output_queue):
        """
        Acquire and hold a write lock until instructed to release it.
        """
        print("Waiting to acquire write lock for {}".format(name))
        with grype_wrapper.write_lock_access() as acquired:
            output_queue.put(name)
            print("Write lock acquired for {} - {}".format(name, acquired))
            if input_queue.get(block=True):
                print("Releasing write lock for {}".format(name))
                return

    @staticmethod
    def value_in_queue(queue, value, timeout=None):
        """
        Check if a value is in the queue. Block with optional timeout.
        """
        try:
            result = queue.get(block=True, timeout=timeout)
            if result == value:
                return True
        except Empty:
            pass
        return False

    def test_simultaneous_read(self):
        """
        Tests that two threads reading at the same time is possible.
        """
        grype_wrapper = TestGrypeWrapperSingleton.get_instance()
        # This queue will be used to tell threads to release the lock.
        instruction_queue = Queue()
        # This queue will be used for the threads to notify whether or not they have acquired the lock.
        output_queue = Queue()

        reader_1_name = "a"
        reader_2_name = "b"

        a = Thread(
            target=self.hold_read_lock,
            args=(grype_wrapper, reader_1_name, instruction_queue, output_queue),
        )
        b = Thread(
            target=self.hold_read_lock,
            args=(grype_wrapper, reader_2_name, instruction_queue, output_queue),
        )

        a.start()
        b.start()

        # Both thread should be holding the lock at this point.
        acquired_tasks = []
        for x in range(2):
            acquired_tasks.append(output_queue.get(block=True, timeout=3))
        assert reader_1_name in acquired_tasks
        assert reader_2_name in acquired_tasks

        # Tell the threads that they can release.
        instruction_queue.put(True)
        instruction_queue.put(True)
        a.join()
        b.join()

    def test_simultaneous_write(self):
        """
        Tests that two threads writing at the same time is not possible.
        """
        grype_wrapper = TestGrypeWrapperSingleton.get_instance()

        # These queues will be used to tell threads to release the lock.
        writer_1_instruction_queue = Queue()
        writer_2_instruction_queue = Queue()

        # This queue will be used for the threads to notify whether or not they have acquired the lock.
        output_queue = Queue()

        writer_1_name = "a"
        writer_2_name = "b"

        writer_1 = Thread(
            target=self.hold_write_lock,
            args=(
                grype_wrapper,
                writer_1_name,
                writer_1_instruction_queue,
                output_queue,
            ),
        )
        writer_2 = Thread(
            target=self.hold_write_lock,
            args=(
                grype_wrapper,
                writer_2_name,
                writer_2_instruction_queue,
                output_queue,
            ),
        )

        # Start the first writer and check that it has acquired the lock.
        writer_1.start()

        acquired_writer_1 = self.value_in_queue(output_queue, writer_1_name, 3)
        assert acquired_writer_1

        # Start the second writer and check that is has not acquired the lock.
        writer_2.start()

        acquired_writer_2 = self.value_in_queue(output_queue, writer_2_name, 3)
        assert not acquired_writer_2

        # Tell the first writer to release the lock.
        writer_1_instruction_queue.put(True)
        writer_1.join()

        # Check that the second writer has acquired the lock.
        acquired_writer_2 = self.value_in_queue(output_queue, writer_2_name, 3)
        assert acquired_writer_2

        # Tell the second writer to release the lock.
        writer_2_instruction_queue.put(True)
        writer_2.join()

    def test_simultaneous_write_while_reading(self):
        """
        Tests that one thread cannot write while another thread is already reading.
        """
        grype_wrapper = TestGrypeWrapperSingleton.get_instance()

        # These queues will be used to tell threads to release the lock.
        reader_instruction_queue = Queue()
        writer_instruction_queue = Queue()

        # This queue will be used for the threads to notify whether or not they have acquired the lock.
        output_queue = Queue()

        writer_name = "a"
        reader_name = "b"

        reader = Thread(
            target=self.hold_read_lock,
            args=(grype_wrapper, reader_name, reader_instruction_queue, output_queue),
        )
        writer = Thread(
            target=self.hold_write_lock,
            args=(grype_wrapper, writer_name, writer_instruction_queue, output_queue),
        )

        # Start the reader and check that it has acquired the lock.
        reader.start()

        acquired_read = self.value_in_queue(output_queue, reader_name, 3)
        assert acquired_read

        # Start the writer and check that is has not acquired the lock.
        writer.start()

        acquired_write = self.value_in_queue(output_queue, writer_name, 3)
        assert not acquired_write

        # Tell the reader to release the lock.
        reader_instruction_queue.put(True)
        reader.join()

        # Check that the writer has acquired the lock.
        acquired_write = self.value_in_queue(output_queue, writer_name, 3)
        assert acquired_write

        # Tell the writer to release the lock.
        writer_instruction_queue.put(True)
        writer.join()

    def test_simultaneous_read_while_writing(self):
        """
        Tests that one thread cannot read while another thread is already writing.
        """
        grype_wrapper = TestGrypeWrapperSingleton.get_instance()

        # These queues will be used to tell threads to release the lock.
        reader_instruction_queue = Queue()
        writer_instruction_queue = Queue()

        # This queue will be used for the threads to notify whether or not they have acquired the lock.
        output_queue = Queue()

        writer_name = "a"
        reader_name = "b"

        reader = Thread(
            target=self.hold_read_lock,
            args=(grype_wrapper, reader_name, reader_instruction_queue, output_queue),
        )
        writer = Thread(
            target=self.hold_write_lock,
            args=(grype_wrapper, writer_name, writer_instruction_queue, output_queue),
        )

        # Start the writer and check that it has acquired the lock.
        writer.start()

        acquired_write = self.value_in_queue(output_queue, writer_name, 3)
        assert acquired_write

        # Start the reader and check that is has not acquired the lock.
        reader.start()

        acquired_read = self.value_in_queue(output_queue, reader_name, 3)
        assert not acquired_read

        # Tell the writer to release the lock.
        writer_instruction_queue.put(True)
        writer.join()

        # Check that the reader has acquired the lock.
        acquired_read = self.value_in_queue(output_queue, reader_name, 3)
        assert acquired_read

        # Tell the reader to release the lock.
        reader_instruction_queue.put(True)
        reader.join()
