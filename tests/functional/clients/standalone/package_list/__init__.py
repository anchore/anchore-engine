import pytest

#
# Preloaded fixtures, with pytest.param that allows a nicer repr when the test runs, instead of the
# default which slaps the whole (giant) dictionary, making output unreadable.
#


def package_path(path):
    """
    Produce a recognizable path name for a package. For the input of:

    /usr/lib/node_modules/npm/node_modules/has/package.json

    Instead of getting just the last part (which would be `package.json` for almost every
    JS package) it would be: `has/package.json`
    """
    parts = path.split("/")
    return "/".join(parts[-2:])


def path_params(pkgs):
    """
    A helper to produce a list of tuples with better output when Pytest runs.
    By default, Pytest will use the full value of the string, which in the case
    of these fixtures is too long, causing unreadable output.
    """
    return [pytest.param(path, id=package_path(path)) for path, _ in pkgs.items()]


def metadata_params(pkgs, fields=None):
    """
    Similarly to `path_params`, the idea is to produce readable output when
    running pytest by using `pytest.param` and reduced string representation
    from the values passed in.
    """
    if fields:
        params = []
        for field in fields:
            params += [
                pytest.param(
                    path,
                    metadata,
                    field,
                    id="field={} element={}".format(
                        repr(field), repr(path.split("/")[-1])
                    ),
                )
                for path, metadata in pkgs.items()
            ]
        return params

    return [
        pytest.param(path, metadata, id=package_path(path))
        for path, metadata in pkgs.items()
    ]
