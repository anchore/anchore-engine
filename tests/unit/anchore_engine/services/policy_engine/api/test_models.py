import datetime

from anchore_engine.common.models.policy_engine import (
    CpeVulnerability,
    CvssCombined,
    CvssScore,
    FeedGroupMetadata,
    FeedMetadata,
    Image,
    ImageIngressRequest,
    ImageIngressResponse,
    ImageVulnerabilityListing,
    LegacyMultiReport,
    LegacyTableReport,
    LegacyVulnerabilityReport,
)
from anchore_engine.utils import datetime_to_rfc3339


def test_feeds():
    f = FeedMetadata()
    f.name = "feed1"
    d1 = datetime.datetime.utcnow()
    f.updated_at = d1
    assert f.to_json() == {
        "name": "feed1",
        "updated_at": datetime_to_rfc3339(d1),
        "groups": None,
        "enabled": None,
        "last_full_sync": None,
        "created_at": None,
    }

    f.groups = []
    g = FeedGroupMetadata()
    g.name = "group1"
    g.record_count = 10
    g.enabled = True
    f.groups.append(g)

    assert f.to_json() == {
        "name": "feed1",
        "updated_at": datetime_to_rfc3339(d1),
        "enabled": None,
        "last_full_sync": None,
        "created_at": None,
        "groups": [
            {
                "name": "group1",
                "enabled": True,
                "record_count": 10,
                "created_at": None,
                "updated_at": None,
                "last_sync": None,
            }
        ],
    }


def test_groups():
    d1 = datetime.datetime.utcnow()
    d2 = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    g = FeedGroupMetadata()
    g.name = "group"
    g.enabled = True
    g.created_at = d2
    g.updated_at = d1
    g.last_sync = d1
    g.record_count = 0
    assert g.to_json() == {
        "name": "group",
        "enabled": True,
        "created_at": datetime_to_rfc3339(d2),
        "updated_at": datetime_to_rfc3339(d1),
        "last_sync": datetime_to_rfc3339(d1),
        "record_count": 0,
    }


def test_image():
    """
    Simple serialization test
    :return:
    """

    i = Image()
    i.user_id = "user"
    i.id = "image1"
    i.state = "active"
    i.digest = "digest"
    i.tags = ["tag1", "tag2"]
    assert i.to_json() == {
        "id": "image1",
        "user_id": "user",
        "digest": "digest",
        "tags": ["tag1", "tag2"],
        "state": "active",
        "created_at": None,
        "last_modified": None,
        "distro_namespace": None,
    }


def test_ingress_request():
    """
    Simple serialization test
    :return:
    """

    r = ImageIngressRequest()
    r.user_id = "user"
    r.image_id = "image1"
    r.fetch_url = "catalog://something.com/user/image_analysis/image1"
    assert r.to_json() == {
        "user_id": "user",
        "image_id": "image1",
        "fetch_url": "catalog://something.com/user/image_analysis/image1",
    }

    r = ImageIngressRequest()
    r.user_id = "user"
    r.image_id = "image1"
    r.fetch_url = "https://someserver.com/file"
    assert r.to_json() == {
        "user_id": "user",
        "image_id": "image1",
        "fetch_url": "https://someserver.com/file",
    }

    r = ImageIngressRequest()
    r.user_id = "user"
    r.image_id = "image1"
    r.fetch_url = "file:///path/to/file"
    assert r.to_json() == {
        "user_id": "user",
        "image_id": "image1",
        "fetch_url": "file:///path/to/file",
    }


def test_ingress_response():
    """
    Simple serialization test
    :return:
    """

    r = ImageIngressResponse()
    r.status = "ok"
    r.problems = []
    assert r.to_json() == {"status": "ok", "problems": []}

    r = ImageIngressResponse()
    assert r.to_json() == {
        "status": None,
        "problems": None,
    }


def test_vuln_report():
    r = ImageVulnerabilityListing()
    r.image_id = "image"
    r.user_id = "user"
    r.cpe_report = [CpeVulnerability()]
    v = r.cpe_report[0]
    v.name = "lib1"
    v.cpe = "cpe:*:*"
    v.cpe23 = "cpe2:*:*"
    v.version = "1.1"
    v.feed_name = "nvdv2"
    v.feed_namespace = "nvdv2:cpes"
    v.severity = "High"
    v.vulnerability_id = "CVE"
    v.vendor_data = [CvssCombined()]
    v.vendor_data[0].id = "CVE-VENDOR"
    v.vendor_data[0].cvss_v2 = CvssScore()
    v.vendor_data[0].cvss_v2.base_score = 1.0
    v.vendor_data[0].cvss_v2.exploitability_score = 2.0
    v.vendor_data[0].cvss_v2.impact_score = 3.0
    v.vendor_data[0].cvss_v3 = CvssScore()
    v.vendor_data[0].cvss_v3.base_score = 1.0
    v.vendor_data[0].cvss_v3.exploitability_score = 2.0
    v.vendor_data[0].cvss_v3.impact_score = 3.0
    v.nvd_data = [CvssCombined()]
    v.nvd_data[0].id = "CVE-NVD"
    v.nvd_data[0].cvss_v2 = CvssScore()
    v.nvd_data[0].cvss_v2.base_score = 1.1
    v.nvd_data[0].cvss_v2.exploitability_score = 2.2
    v.nvd_data[0].cvss_v2.impact_score = 3.3
    v.nvd_data[0].cvss_v3 = CvssScore()
    v.nvd_data[0].cvss_v3.base_score = 1.1
    v.nvd_data[0].cvss_v3.exploitability_score = 2.2
    v.nvd_data[0].cvss_v3.impact_score = 3.3
    r.legacy_report = LegacyVulnerabilityReport()
    r.legacy_report.multi = LegacyMultiReport()
    r.legacy_report.multi.result = LegacyTableReport()
    r.legacy_report.multi.result.colcount = 4
    r.legacy_report.multi.result.rowcount = 1
    r.legacy_report.multi.result.header = ["id", "name", "version", "url"]
    r.legacy_report.multi.result.rows = [["CVE-NVD", "lib1", "1.1", "http://someurl"]]
    r.legacy_report.multi.url_column_index = 3
    r.legacy_report.multi.warns = []

    assert r.to_json() == {
        "user_id": "user",
        "image_id": "image",
        "cpe_report": [
            {
                "cpe": "cpe:*:*",
                "cpe23": "cpe2:*:*",
                "pkg_path": None,
                "pkg_type": None,
                "feed_name": "nvdv2",
                "feed_namespace": "nvdv2:cpes",
                "version": "1.1",
                "name": "lib1",
                "link": None,
                "nvd_data": [
                    {
                        "id": "CVE-NVD",
                        "cvss_v2": {
                            "base_score": 1.1,
                            "exploitability_score": 2.2,
                            "impact_score": 3.3,
                        },
                        "cvss_v3": {
                            "base_score": 1.1,
                            "exploitability_score": 2.2,
                            "impact_score": 3.3,
                        },
                    }
                ],
                "vendor_data": [
                    {
                        "id": "CVE-VENDOR",
                        "cvss_v2": {
                            "base_score": 1.0,
                            "exploitability_score": 2.0,
                            "impact_score": 3.0,
                        },
                        "cvss_v3": {
                            "base_score": 1.0,
                            "exploitability_score": 2.0,
                            "impact_score": 3.0,
                        },
                    }
                ],
                "severity": "High",
                "vulnerability_id": "CVE",
            }
        ],
        "legacy_report": {
            "multi": {
                "result": {
                    "colcount": 4,
                    "header": ["id", "name", "version", "url"],
                    "rowcount": 1,
                    "rows": [["CVE-NVD", "lib1", "1.1", "http://someurl"]],
                },
                "url_column_index": 3,
                "warns": [],
            }
        },
    }
