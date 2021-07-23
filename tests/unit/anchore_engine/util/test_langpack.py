import pytest

from anchore_engine.util.langpack import compare_versions

enable_training = False

all_languages = ["java", "maven", "js", "npm", "ruby", "gem", "nuget", "python"]
generic_languages = ["js", "npm", "ruby", "gem", "nuget"]

lesser_versions = [
    "0.0",
    "1",
    "1.0",
    "1.0.1",
    "1.0.0.1",
]

greater_versions = [
    "2",
    "2.1",
    "2.0.1",
    "2.0.0.0",
]

greater_versions_rc = [
    "%s-%s" % (ver, rc)
    for ver in greater_versions
    for rc in ["rc1", "rc.1", "rc1.10001.11"]
]

lesser_versions_rc = [
    "%s-%s" % (ver, rc)
    for ver in lesser_versions
    for rc in ["rc1", "rc.1", "rc1.10001.11"]
]


greater_than_operators = [">", ">="]
lesser_than_operators = ["<", "<="]


@pytest.fixture(
    params=[
        "%s %s" % (op, ver) for op in greater_than_operators for ver in lesser_versions
    ]
)
def greater_than_versions(request):
    # > 0.0.1
    return request.param


@pytest.fixture(
    params=[
        "%s %s" % (op, ver) for op in greater_than_operators for ver in greater_versions
    ]
)
def greater_than_versions_high(request):
    # > 2.0.0
    return request.param


@pytest.fixture(
    params=[
        "%s %s" % (op, ver)
        for op in greater_than_operators
        for ver in lesser_versions_rc
    ]
)
def greater_than_rc_versions(request):
    # > 0.0.1-rc1
    return request.param


@pytest.fixture(
    params=[
        "%s %s" % (op, ver) for op in lesser_than_operators for ver in greater_versions
    ]
)
def lesser_than_versions(request):
    # < 2.0.0
    return request.param


@pytest.fixture(
    params=[
        "%s %s" % (op, ver) for op in lesser_than_operators for ver in lesser_versions
    ]
)
def lesser_than_versions_low(request):
    # < 2.0.0
    return request.param


@pytest.fixture(
    params=[
        "%s %s" % (op, ver)
        for op in lesser_than_operators
        for ver in greater_versions_rc
    ]
)
def lesser_than_rc_versions(request):
    # < 2.0.0-rc1
    return request.param


is_match = [
    ("=1", "1"),
    ("<=1", "1"),
    ("<1", "0"),
    (">=1", "1"),
    (">1", "2"),
    ("!=1", "2"),
    ("!=1", "all"),
    ("!=1", "*"),
    ("*", "*"),
    ("=1", "1"),
    ("=1.0", "1.0"),
    ("=1.0.0", "1.0.0"),
    ("=1.0.0.0", "1.0.0.0"),
    (">1", "2"),
    (">1.0", "2"),
    (">1.0.0", "2"),
    (">1.0.0.0", "2"),
    (">1", "2"),
    (">1", "2.0"),
    (">1", "2.0.0"),
    (">1", "2.0.0.0"),
    (">0", "blah"),
    (">0.0", "blah"),
    (">0.0.0", "blah"),
    (">0.0.0.0", "blah"),
    (">1.0.0 <2.0.0", "1.5.0"),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", "0.0.5"),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", "1.0.5"),
    ("~1", "1"),
    ("~1.1", "1.1"),
    ("~1.1", "1.1.1"),
    ("~1.1", "1.1.99"),
    ("~1.0.0", "1.0.0"),
    ("~1.0.0", "1.0.1"),
    ("~1.0.0", "1.0.99"),
    ("~1.0.0-rc.2", "1.0.0-rc.3"),
    ("^1", "1"),
    ("^1", "1.0"),
    ("^1", "1.1"),
    ("^1", "1.2"),
    ("^1.1", "1.1"),
    ("^1.1", "1.2"),
    ("^1.1", "1.1.1"),
    ("^1.1", "1.1.99"),
    ("^1.1.0", "1.1.0"),
    ("^1.1.0", "1.2.0"),
    ("^1.1.0", "1.1.1"),
    ("^1.1.0", "1.1.99"),
    ("^1.0.0-rc.2", "1.0.0-rc.3"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc1.10001.12"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc1.10002.11"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc2.10001.11"),
]


doesnt_match = [
    ("=1", "2"),
    ("<=1", "2"),
    ("<1", "2"),
    (">=1", "0"),
    (">1", "1"),
    ("!=1", "1"),
    (">1", "all"),
    (">1", "*"),
    ("<0", "blah"),
    ("<0.0", "blah"),
    ("<0.0.0", "blah"),
    ("<0.0.0.0", "blah"),
    ("<0", "0"),
    ("<0.0", "0"),
    ("<0.0.0", "0"),
    ("<0.0.0.0", "0"),
    (">1.0.0 <2.0.0", "0.0.5"),
    (">1.0.0 <2.0.0", "2.5.0"),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", "0.0.0"),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", "1.0.0"),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", "2.0.0"),
    ("~1", "2"),
    ("~1.1", "2.0"),
    ("~1.1", "1.2"),
    ("~1.1", "1.0"),
    ("~1.0.0", "2.0.0"),
    ("~1.0.0", "1.1.0"),
    ("~1.0.0-rc.2", "2.0.0"),
    ("~1.0.0-rc.2", "1.0.0-rc.1"),
    ("^1", "2"),
    ("^1.1", "2.0"),
    ("^1.1", "1.0"),
    ("^1.1.0", "2.0.0"),
    ("^1.1.0", "1.0.0"),
    ("^1.0.0-rc.2", "2.0.0"),
    ("^1.0.0-rc.2", "1.0.0-rc.1"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc1.10001.10"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc1.10000.11"),
    (">1.0.0-rc1.10001.11", "1.0.0-rc0.10001.11"),
]


error_matches = [
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", ""),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", None),
    (">0.0.1 <0.0.9 || >1.0.1 <1.0.9", []),
    ("", "1"),
    (None, "1"),
    ([], "1"),
    (">==1", "1"),
    (">>1", "1"),
    ("blah", "1"),
    ("-1.0", "1"),
]

# "generic" becuase they are handled specifically without Java and Python

matches_generic_languages = [
    (">0", "1-beta-1234"),
    (">0", "1.0.0.0-beta-1234"),
    (">0", "1-preview9.19421.4"),
    (">0", "1.0.0.0-preview9.19421.4"),
    (">1.0.0-rc1-100729", "1.0.0"),
    (">1.0.0-rc1-100729", "1"),
]

doesnt_match_generic_languages = [
    (">1", "1-beta-1234"),
    (">1", "1.0.0.0-beta-1234"),
    (">1", "1-preview9.19421.4"),
    (">1", "1.0.0.0-preview9.19421.4"),
    (">1.0.0-rc1-100729", "1-rc1"),
    (">1.0.0-rc1-100729", "1.0.0-rc1"),
]


class TestSemver:
    @pytest.mark.parametrize("left,right", is_match)
    @pytest.mark.parametrize("lang", all_languages)
    def test_matches(self, left, right, lang):
        assert compare_versions(left, right, lang) is True

    @pytest.mark.parametrize("left,right", doesnt_match)
    @pytest.mark.parametrize("lang", all_languages)
    def test_doesnt_match(self, left, right, lang):
        assert compare_versions(left, right, lang) is False

    def test_unsupported(self):
        with pytest.raises(Exception):
            compare_versions("> 1.0", "1.0", "VimScript")

    @pytest.mark.parametrize("left,right", error_matches)
    @pytest.mark.parametrize("lang", all_languages)
    def test_error_matches(self, left, right, lang):
        with pytest.raises(Exception):
            compare_versions(left, right, lang)

    @pytest.mark.parametrize("left,right", matches_generic_languages)
    @pytest.mark.parametrize("lang", generic_languages)
    def test_matches_generic_languages(self, left, right, lang):
        assert compare_versions(left, right, lang) is True

    @pytest.mark.parametrize("left,right", doesnt_match_generic_languages)
    @pytest.mark.parametrize("lang", generic_languages)
    def test_doesnt_match_generic_languages(self, left, right, lang):
        assert compare_versions(left, right, lang) is False


@pytest.mark.parametrize("right", greater_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_greater_than(greater_than_versions, right, lang):
    assert compare_versions(greater_than_versions, right, lang) is True


@pytest.mark.parametrize("right", greater_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_greater_than_rc(greater_than_rc_versions, right, lang):
    assert compare_versions(greater_than_rc_versions, right, lang) is True


@pytest.mark.parametrize("right", lesser_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_lesser_than(lesser_than_versions, right, lang):
    assert compare_versions(lesser_than_versions, right, lang) is True


@pytest.mark.parametrize("right", lesser_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_lesser_than_rc(lesser_than_rc_versions, right, lang):
    assert compare_versions(lesser_than_rc_versions, right, lang) is True


@pytest.mark.parametrize("right", lesser_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_not_greater_than(greater_than_versions_high, right, lang):
    assert compare_versions(greater_than_versions_high, right, lang) is False


@pytest.mark.parametrize("right", greater_versions)
@pytest.mark.parametrize("lang", all_languages)
def test_not_lesser_than(lesser_than_versions_low, right, lang):
    assert compare_versions(lesser_than_versions_low, right, lang) is False
