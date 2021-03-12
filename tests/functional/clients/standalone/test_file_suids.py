import pytest

base_file_suids = [("/test_file", "0o4644")]


@pytest.mark.parametrize("path, suid", base_file_suids)
def test_file_suids(analyzed_data, path, suid):
    data = analyzed_data("suids")
    base = data["image"]["imagedata"]["analysis_report"]["file_suids"]["files.suids"][
        "base"
    ]
    assert base[path] == suid
