import pytest


@pytest.fixture(scope="session")
def monkeysession(request):
    """
    This is an unfortunate kludge needed to force the monkeypatch fixture to
    allow a specific scope (the whole test session in this case).

    Without this, Pytest would raise an error explaining this is not possible.

    See: https://github.com/pytest-dev/pytest/issues/363

    If this ever stops working, then the `monkeypatch` needs to be done on
    every test method *or* the scope needs to be removed, causing these to be
    set for every test.
    """
    from _pytest.monkeypatch import MonkeyPatch

    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()
