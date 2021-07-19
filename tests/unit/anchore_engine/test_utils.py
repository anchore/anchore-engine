import pytest

from anchore_engine.utils import (
    SANITIZE_CMD_ERROR_MESSAGE,
    CommandException,
    run_check,
    run_command_list_with_piped_input,
    run_sanitize,
)

from anchore_engine.util.docker import parse_dockerimage_string

images = [
    (
        "docker.io/library/nginx",
        {
            "digest": None,
            "fulldigest": None,
            "fulltag": "docker.io/library/nginx:latest",
            "host": "docker.io",
            "imageId": None,
            "port": None,
            "pullstring": "docker.io/library/nginx:latest",
            "registry": "docker.io",
            "repo": "library/nginx",
            "repotag": "library/nginx:latest",
            "tag": "latest",
        },
    ),
    (
        "docker.io/nginx",
        {
            "digest": None,
            "fulldigest": None,
            "fulltag": "docker.io/nginx:latest",
            "host": "docker.io",
            "imageId": None,
            "port": None,
            "pullstring": "docker.io/nginx:latest",
            "registry": "docker.io",
            "repo": "nginx",
            "repotag": "nginx:latest",
            "tag": "latest",
        },
    ),
    (
        "nginx",
        {
            "digest": None,
            "fulldigest": None,
            "fulltag": "docker.io/nginx:latest",
            "host": "docker.io",
            "imageId": None,
            "port": None,
            "pullstring": "docker.io/nginx:latest",
            "registry": "docker.io",
            "repo": "nginx",
            "repotag": "nginx:latest",
            "tag": "latest",
        },
    ),
    (
        "docker.io/library/nginx@sha256:abcdef123",
        {
            "digest": "sha256:abcdef123",
            "fulldigest": "docker.io/library/nginx@sha256:abcdef123",
            "fulltag": None,
            "host": "docker.io",
            "imageId": None,
            "port": None,
            "pullstring": "docker.io/library/nginx@sha256:abcdef123",
            "registry": "docker.io",
            "repo": "library/nginx",
            "repotag": None,
            "tag": None,
        },
    ),
    (
        "docker.io/nginx@sha256:abcdef123",
        {
            "digest": "sha256:abcdef123",
            "fulldigest": "docker.io/nginx@sha256:abcdef123",
            "fulltag": None,
            "host": "docker.io",
            "imageId": None,
            "port": None,
            "pullstring": "docker.io/nginx@sha256:abcdef123",
            "registry": "docker.io",
            "repo": "nginx",
            "repotag": None,
            "tag": None,
        },
    ),
]


@pytest.mark.parametrize("image,expected", images)
def test_parse_dockerimage_string(image, expected):
    result = parse_dockerimage_string(image)
    assert result == expected


def test_run_sanitize_good_input():
    # Setup input
    input_cmd_list = ["wc", "-l"]

    # Function under test
    output_cmd_list = run_sanitize(input_cmd_list)

    # Validate output
    output_cmd_list == input_cmd_list


@pytest.mark.parametrize(
    "input",
    [";&<>", ";", "&", "<", ">"],
)
def test_run_sanitize_bad_input(input):
    with pytest.raises(Exception) as error:
        # Function under test
        run_sanitize(input)

    # Validate error message
    assert str(error.value) == SANITIZE_CMD_ERROR_MESSAGE


@pytest.mark.parametrize(
    "cmd_list, input_data, expected_return_code, expected_stdout, expected_stderr",
    [
        (["wc", "-l"], "", 0, "0", b""),
    ],
)
def test_run_command_list_with_piped_input(
    cmd_list, input_data, expected_return_code, expected_stdout, expected_stderr
):
    # Function under test
    return_code, stdout, stderr = run_command_list_with_piped_input(
        cmd_list, input_data
    )

    # Binary string returned in different environments can be padded with different amounts of whitespace
    # So convert it to utf-8 and trim it so we get a clean, reliable comparison
    if stdout is not None:
        stdout = stdout.decode("utf-8").strip()

    # Validate input
    assert return_code == expected_return_code
    assert stdout == expected_stdout
    assert stderr == expected_stderr


@pytest.mark.parametrize(
    "cmd_list, input_data, expected_stdout, expected_stderr",
    [
        (["wc", "-l"], "", "0", ""),
        (["wc", "-l"], "hello\nworld", "1", ""),
    ],
)
def test_run_check_with_input(cmd_list, input_data, expected_stdout, expected_stderr):
    # Function under test
    stdout, stderr = run_check(cmd_list, input_data)

    # Binary string returned in different environments can be padded with different amounts of whitespace
    # So convert it to utf-8 and trim it so we get a clean, reliable comparison
    if stdout is not None:
        stdout = stdout.strip()

    # Validate input
    assert stdout == expected_stdout
    assert stderr == expected_stderr


@pytest.mark.parametrize("cmd_list", [[], None])
def test_run_check_invalid_cmd_list(cmd_list):
    with pytest.raises(Exception) as error:
        # Function under test
        run_check(cmd_list)


# allows raising from a lambda
def _raise(exc):
    raise exc


class FakePopen:
    def __init__(self, code, stdout, stderr, raises=None):
        self.returncode = code
        self.stdout = stdout
        self.stderr = stderr
        self.raises = raises

    def __call__(self, *a, **kw):
        if self.raises is not None:
            raise self.raises

        return self

    def communicate(self):
        if self.raises is not None:
            raise self.raises

        return self.stdout, self.stderr


class Capture:
    """
    Remember everything that was called, optionally return them
    """

    def __init__(self, *a, **kw):
        self.a = a
        self.kw = kw
        self.calls = []
        self.return_values = kw.get("return_values", False)
        self.always_returns = kw.get("always_returns", False)

    def __call__(self, *a, **kw):
        self.calls.append({"args": a, "kwargs": kw})
        if self.always_returns:
            return self.always_returns
        if self.return_values:
            return self.return_values.pop()


class TestRunCheck:
    def test_file_not_found(self, monkeypatch):
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            lambda a, **kw: _raise(FileNotFoundError),
        )
        with pytest.raises(CommandException) as error:
            run_check(["foobar", "-vvv"])

        assert "unable to run command. Executable does not exist" in str(error)
        assert error.value.code == 1
        assert error.value.cmd == "foobar -vvv"

    def test_capture_string_std(self, monkeypatch):
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(0, "stdout\nline", "stderr\nline"),
        )
        stdout, stderr = run_check(["ls"])
        assert stdout == "stdout\nline"
        assert stderr == "stderr\nline"

    def test_capture_bytes_std(self, monkeypatch):
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(0, b"stdout\nline", b"stderr\nline"),
        )
        stdout, stderr = run_check(["ls"])
        assert stdout == "stdout\nline"
        assert stderr == "stderr\nline"

    def test_log_stdout(self, monkeypatch):
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(0, "stdout\nline", b"stderr\nline"),
        )

        debug_log = Capture()
        monkeypatch.setattr("anchore_engine.utils.logger.debug", debug_log)
        stdout, stderr = run_check(["ls"])
        assert debug_log.calls[0]["args"] == ("running cmd: %s", "ls")
        assert debug_log.calls[1]["args"] == ("stdout: %s", "stdout")
        assert debug_log.calls[2]["args"] == (
            "stdout: %s",
            "line",
        )

    def test_log_stderr_does_not_log(self, monkeypatch):
        # a 0 exit status doesn't log stderr
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(0, "stdout\nline", "stderr\nline"),
        )

        error_log = Capture()
        monkeypatch.setattr("anchore_engine.utils.logger.error", error_log)
        stdout, stderr = run_check(["ls"])
        assert error_log.calls == []

    def test_raises_on_non_zero(self, monkeypatch):
        # a 0 exit status doesn't log stderr
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(100, "gathering info", "error! bad input"),
        )

        error_log = Capture()
        monkeypatch.setattr("anchore_engine.utils.logger.error", error_log)
        with pytest.raises(CommandException) as error:
            stdout, stderr = run_check(["ls"])

        assert error.value.msg == "Non-zero exit status code when running subprocess"

    def test_non_zero_doesnt_log_error(self, monkeypatch):
        # at debug levels the stderr output is already logged
        # set the log level to 4 (DEBUG)
        monkeypatch.setattr("anchore_engine.utils.logger.log_level", 4)
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(100, "gathering info", "error! bad input"),
        )

        error_log = Capture()
        debug_log = Capture()
        monkeypatch.setattr("anchore_engine.utils.logger.error", error_log)
        monkeypatch.setattr("anchore_engine.utils.logger.debug", debug_log)
        with pytest.raises(CommandException):
            stdout, stderr = run_check(["ls"])

        assert len(error_log.calls) == 0
        assert len(debug_log.calls) == 3

    def test_non_zero_logs_error(self, monkeypatch):
        # set the log level to 2 (WARNING)
        monkeypatch.setattr("anchore_engine.utils.logger.log_level", 2)
        monkeypatch.setattr(
            "anchore_engine.utils.subprocess.Popen",
            FakePopen(100, "gathering info", "error! bad input"),
        )

        error_log = Capture()
        debug_log = Capture()
        monkeypatch.setattr("anchore_engine.utils.logger.error", error_log)
        monkeypatch.setattr("anchore_engine.utils.logger.debug", debug_log)
        with pytest.raises(CommandException):
            stdout, stderr = run_check(["ls"])

        assert len(error_log.calls) == 1
