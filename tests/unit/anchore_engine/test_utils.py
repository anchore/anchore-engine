import pytest
from anchore_engine.utils import parse_dockerimage_string, run_check, CommandException


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
