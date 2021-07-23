import pytest

from anchore_engine.db import Image, get_thread_scoped_session
from anchore_engine.services.policy_engine.engine.policy.gates.vulnerabilities import (
    FeedOutOfDateTrigger,
    UnsupportedDistroTrigger,
    VulnerabilitiesGate,
    VulnerabilityMatchTrigger,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()


@pytest.mark.usefixtures("cls_fully_loaded_test_env")
class AnchoreSecGateTest(GateUnitTest):
    """
    Test against the debian 8 based "node" image in the test env.
    It contains the package:
    mercurial 3.1.2-2+deb8u3

    Vuln data for testing:

    [
    {
    "Vulnerability": {
      "FixedIn": [
        {
          "VersionFormat": "dpkg",
          "NamespaceName": "debian:8",
          "Version": "None",
          "Name": "mercurial"
        }
      ],
      "NamespaceName": "debian:8",
      "Link": "https://fake.cve.testing/tracker/CVE-TEST-TEST0",
      "Name": "CVE-TEST-TEST0",
      "Severity": "Low"
    }
    },
    {
    "Vulnerability": {
      "FixedIn": [
        {
          "VersionFormat": "dpkg",
          "NamespaceName": "debian:8",
          "Version": "3.1.2-2+deb8u3",
          "Name": "mercurial"
        }
      ],
      "NamespaceName": "debian:8",
      "Link": "https://fake.cve.testing/tracker/CVE-TEST-TEST1",
      "Name": "CVE-TEST-TEST1",
      "Severity": "Medium"
    }
    },
    {
    "Vulnerability": {
      "FixedIn": [
        {
          "VersionFormat": "dpkg",
          "NamespaceName": "debian:8",
          "Version": "3.1.1-2+deb8u3",
          "Name": "mercurial"
        }
      ],
      "NamespaceName": "debian:8",
      "Link": "https://fake.cve.testing/tracker/CVE-TEST-TEST2",
      "Name": "CVE-TEST-TEST2",
      "Severity": "High"
    }
    },
    {
    "Vulnerability": {
      "FixedIn": [
        {
          "VersionFormat": "dpkg",
          "NamespaceName": "debian:8",
          "Version": "3.1.3-2+deb8u3",
          "Name": "mercurial"
        }
      ],
      "NamespaceName": "debian:8",
      "Link": "https://fake.cve.testing/tracker/CVE-TEST-TEST3",
      "Name": "CVE-TEST-TEST3",
      "Severity": "Critical"
    }
    }
    ]


    The debian:8 feed vuln data is purely fake and for testing against this package specifically

    """

    gate_clazz = VulnerabilitiesGate
    __default_image__ = "node"

    def test_unsupported_distro(self):
        t, gate, test_context = self.get_initialized_trigger(
            UnsupportedDistroTrigger.__trigger_name__
        )
        db = get_thread_scoped_session()
        image = db.query(Image).get(
            (self.test_env.get_images_named("busybox")[0][0], "0")
        )
        test_context = gate.prepare_context(image, test_context)
        t.evaluate(image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(len(t.fired), 1)

    def test_feedoutofdate(self):
        t, gate, test_context = self.get_initialized_trigger(
            FeedOutOfDateTrigger.__trigger_name__, max_days_since_sync="0"
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(
            FeedOutOfDateTrigger.__trigger_name__, max_days_since_sync="1000000"
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(len(t.fired), 0)

    def test_all_severity(self):
        t, gate, test_context = self.get_initialized_trigger(
            VulnerabilityMatchTrigger.__trigger_name__,
            package_type="all",
            severity="unknown",
            severity_comparison=">=",
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info("Fired: {}".format(t.fired))
        self.assertGreaterEqual(len(t.fired), 1)

    def test_packages_severity(self):
        t, gate, test_context = self.get_initialized_trigger(
            VulnerabilityMatchTrigger.__trigger_name__,
            package_type="all",
            severity="medium",
            severity_comparison=">=",
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info("Fired: {}".format(t.fired))
        # CVE-TEST-TEST3, all others are either already fixed or < medium
        self.assertGreaterEqual(len(t.fired), 1)

    def test_fixavailableparam(self):
        t, gate, test_context = self.get_initialized_trigger(
            VulnerabilityMatchTrigger.__trigger_name__,
            package_type="all",
            severity="medium",
            severity_comparison=">=",
            fix_available="True",
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info("Fired: {}".format(t.fired))
        # CVE-TEST-TEST3
        self.assertGreaterEqual(len(t.fired), 1)

        t, gate, test_context = self.get_initialized_trigger(
            VulnerabilityMatchTrigger.__trigger_name__,
            fix_available="False",
            severity="unknown",
            severity_comparison=">=",
            package_type="all",
        )
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info("Fired: {}".format(t.fired))
        # CVE-TEST-TEST0
        self.assertGreaterEqual(len(t.fired), 1)
