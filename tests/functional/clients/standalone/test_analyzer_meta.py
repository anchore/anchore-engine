# from ['image']['imagedata']['analysis_report']['analyzer_meta']


def test_distro_metadata(analyzed_data):
    result = analyzed_data()
    actual = result["image"]["imagedata"]["analysis_report"]["analyzer_meta"]
    # This is odd, it nests another `analyzer_meta` in there
    expected = {
        "analyzer_meta": {
            "base": {"DISTRO": "centos", "DISTROVERS": "8", "LIKEDISTRO": "rhel,fedora"}
        }
    }
    assert actual == expected


def test_alpine_metadata(analyzed_data):
    result = analyzed_data("alpine2.6")
    actual = result["image"]["imagedata"]["analysis_report"]["analyzer_meta"]
    expected = {
        "analyzer_meta": {
            "base": {
                "DISTRO": "busybox",
                "DISTROVERS": "v1.21.1",
                "LIKEDISTRO": "busybox",
            }
        }
    }
    assert actual == expected
