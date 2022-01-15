import pytest

from anchore_engine.db.entities.policy_engine import ImageCpe
from anchore_engine.services.policy_engine.engine.loaders import ImageLoader
from anchore_engine.services.policy_engine.engine.vulns import cpes


@pytest.fixture
def cpe_builder():
    def build(cpe_string):
        decomposed_cpe = ImageLoader.decompose_cpe(cpe_string)
        cpe = ImageCpe()
        cpe.cpetype = decomposed_cpe[2]
        cpe.vendor = decomposed_cpe[3]
        cpe.name = decomposed_cpe[4]
        cpe.version = decomposed_cpe[5]
        cpe.update = decomposed_cpe[6]
        cpe.meta = decomposed_cpe[7]
        return cpe

    return build


@pytest.mark.parametrize(
    "lhs, rhs, result",
    [
        ("*", "foo", 1),  # * is less specific
        ("*", "~", 1),
        ("*", "-", 1),
        # TODO falls back to lexicographic comparison which is not good. update logic to cpe 2.3 specs and revisit test
        ("-", "~", 1),
        ("bar", "*", -1),
        ("~", "*", -1),
        ("*", "*", 0),
        ("foo", "foo", 0),
        ("", "", 0),
        ("foo", "bar", -1),
        ("java", "maven", 1),
    ],
)
def test_cpe_field_comparison(lhs, rhs, result):
    assert cpes.compare_fields(lhs, rhs) == result


@pytest.mark.parametrize(
    "lhs, rhs, result",
    [
        # vendor
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:python:*:*",  # more specific
            "cpe:2.3:a:*:urlgrabber:3.10:*:*:*:*:python:*:*",  # less specific
            -1,
        ),
        # name
        (
            "cpe:2.3:a:urlgrabber:*:3.10:*:*:*:*:*:*:*",  # less specific
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",  # more specific
            1,
        ),
        # version
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:*:*:*:*:*:*:*:*",  # less specific
            "cpe:2.3:a:urlgrabber:urlgrabber:~:*:*:*:*:*:*:*",  # more specific
            1,
        ),
        # version
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:x:*:*:*:*:*:*",  # more specific
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",  # less specific
            -1,
        ),
        # meta
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:y:*:*:*:*:*",  # more specific
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",  # less specific
            -1,
        ),
        # version
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:*:*:*:*:*:*:*:*",  # less specific
            "cpe:2.3:a:urlgrabber:urlgrabber:~:*:*:*:*:*:*:*",  # more specific
            1,
        ),
        # both cpes have similar components, so a lexicographic comparison is forced
        (
            "cpe:2.3:a:python-urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",
            1,
        ),
        # same cpes
        (
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",
            "cpe:2.3:a:urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",
            0,
        ),
        # TODO this is not great, the second cpe is more specific and should win. But ImageCpe translation does not store all the attributes
        (
            "cpe:2.3:a:python-urlgrabber:urlgrabber:3.10:*:*:*:*:*:*:*",  # less specific
            "cpe:2.3:a:python-urlgrabber:urlgrabber:3.10:*:*:*:*:python:*:*",  # more specific
            0,
        ),
    ],
)
def test_image_cpe_comparison(lhs, rhs, result, cpe_builder):
    lhs_cpe = cpe_builder(lhs)
    rhs_cpe = cpe_builder(rhs)

    assert cpes.compare_cpes(lhs_cpe, rhs_cpe) == result
