import datetime

import pytest

from anchore_engine.db.entities.policy_engine import Image
from anchore_engine.services.policy_engine.engine.vulns.scanners import LegacyScanner


@pytest.fixture
def alpine_image():
    img = Image()
    img.distro_name = "alpine"
    img.distro_version = "3.10"
    img.id = "abc123abc123"
    img.analysis_artifacts = []
    img.digest = "sha256:abc123abc123"
    img.created_at = datetime.datetime.utcnow()
    img.last_modified = img.created_at
    img.cpes = []
    img.docker_data_json = {}
    img.dockerfile_contents = ""
    img.dockerfile_mode = "guessed"
    img.docker_history_json = []
    img.packages = []
    img.gems = []
    img.npms = []
    img.state = "analyzed"
    img.size = "1000"
    img.user_id = "admin"
    return img


@pytest.fixture
def alpine_with_vulns(alpine_image):
    alpine_image.vulnerabilities = lambda: []
    alpine_image.cpe_vulnerabilities = lambda x, y: []
    return alpine_image


def test_scanner_basic(alpine_with_vulns):
    scanner = LegacyScanner()
    vulns = scanner.get_vulnerabilities(alpine_with_vulns)
    assert vulns == []
