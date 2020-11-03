import pytest

#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#


def path_params(pkgs):
    """
    A helper to produce a list of tuples with better output when Pytest runs.
    By default, Pytest will use the full value of the string, which in the case
    of these fixtures is too long, causing unreadable output.
    """
    return [pytest.param(path, id=path.split("/")[-1]) for path, _ in pkgs]


def metadata_params(pkgs):
    """
    Similarly to `path_params`, the idea is to produce readable output when
    running pytest by using `pytest.param` and reduced string representation
    from the values passed in
    """
    return [
        pytest.param(path, metadata, id=path.split("/")[-1]) for path, metadata in pkgs
    ]
