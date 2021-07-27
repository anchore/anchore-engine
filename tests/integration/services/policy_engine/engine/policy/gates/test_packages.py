import pytest

from anchore_engine.db import (
    Image,
    ImagePackageManifestEntry,
    get_thread_scoped_session,
)
from anchore_engine.services.policy_engine.engine.policy.gates.packages import (
    BlackListTrigger,
    PackagesCheckGate,
    RequiredPackageTrigger,
    VerifyTrigger,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()


@pytest.mark.usefixtures("cls_no_feeds_test_env")
class PackageCheckGateTest(GateUnitTest):
    __default_image__ = "debian9-slim-custom"  # Testing against a specifically broken analysis output (hand edited to fail in predictable ways)
    gate_clazz = PackagesCheckGate

    def test_blacklist(self):

        # Match
        t, gate, test_context = self.get_initialized_trigger(
            BlackListTrigger.__trigger_name__, name="libc6", version="2.24-11+deb9u4"
        )
        db = get_thread_scoped_session()

        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))

        # No match
        t, gate, test_context = self.get_initialized_trigger(
            BlackListTrigger.__trigger_name__, name="libc6", version="2.24-10+deb9u4"
        )
        db = get_thread_scoped_session()
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(0, len(t.fired))

        # Match, name only
        t, gate, test_context = self.get_initialized_trigger(
            BlackListTrigger.__trigger_name__, name="libc6"
        )
        db = get_thread_scoped_session()
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(1, len(t.fired))

        # No match
        t, gate, test_context = self.get_initialized_trigger(
            BlackListTrigger.__trigger_name__, name="libc-not-real"
        )
        db = get_thread_scoped_session()
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.info(("Fired: {}".format(t.fired)))
        self.assertEqual(0, len(t.fired))

    def test_pkg_required(self):
        db = get_thread_scoped_session()
        try:
            image = self.test_image

            # Image has libc6 - 2.24-11+deb9u4

            # Positive tests... should not result in match

            # Require the version in image, no match expected.
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc6",
                version="2.24-11+deb9u4",
                version_match_type="exact",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(0, len(t.fired))

            # Require a min version < than version installed, expect 0 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc6",
                version="2.24-10+deb9u4",
                version_match_type="minimum",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(0, len(t.fired))

            # Requirement not met

            # Require an exact version not present, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc6",
                version="2.24-10+deb9u4",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

            # Require exact match that doesn't match version, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc6",
                version="2.24-10+deb9u4",
                version_match_type="exact",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

            # Require min version > installed version, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc6",
                version="2.24-15+deb9u4",
                version_match_type="minimum",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

            # Require a package not installed, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__, name="libc-not-installed"
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

            # Require a package not installed even with version check, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc-not-installed",
                version="1.1.0",
                version_match_type="exact",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

            # Require a package not installed even with min version chec, expect 1 match
            t, gate, test_context = self.get_initialized_trigger(
                RequiredPackageTrigger.__trigger_name__,
                name="libc-not-installed",
                version="1.1.0",
                version_match_type="minimum",
            )
            test_context = gate.prepare_context(image, test_context)
            t.evaluate(image, test_context)
            logger.info(("Fired: {}".format(t.fired)))
            self.assertEqual(1, len(t.fired))

        finally:
            db.rollback()

    def test_verifytrigger(self):
        """
        Test package verification gate

        Image for testing: debian:9-slim (sha256:d4f7ac076cf641652722c33b026fccd52933bb5c26aa703d3cef2dd5b022422a)
        Since this is a slim image, it is missing a lot of docs pages, so dpkg -V returns 1889 results.

        For this test, specifically focus on data modified
        /usr/share/doc/tzdata/copyright file modified in result report with wrong digests and mode
        /usr/share/doc/tzdata/README.Debian file remove in analysis but present in the pkg db

        Image misses: /usr/share/doc/tzdata/changelog.gz and changelog.Debian.gz without any test-modification, as pulled from dockerhub.

        :return:
        """

        logger.info("Default params check")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        self.assertGreater(
            len(t.fired), 0
        )  # 1890 is the exact number for this specific image
        self.assertTrue(len([x for x in t.fired if "missing" in x.msg]) > 0)
        self.assertTrue(len([x for x in t.fired if "changed" in x.msg]) > 0)

        # self.assertTrue(('missing' in t.fired[0].msg and 'changed' in t.fired[1].msg) or ('missing' in t.fired[1].msg and 'changed' in t.fired[0].msg))

        logger.info("Specific dirs and check only changed")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__,
            only_directories="/usr/share/doc/tzdata/",
            check="changed",
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.debug("Fired: {}".format(t.fired))
        self.assertTrue("changed" in t.fired[0].msg)

        logger.info("Check only missing")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__, check="missing"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.debug("Fired: {}".format(t.fired))
        self.assertGreaterEqual(len(t.fired), 1)

        logger.info("Specific pkg, with issues")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__, only_packages="tzdata"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.debug("Fired: {}".format(t.fired))
        self.assertEqual(len(t.fired), 4)

        logger.info("Specific pkg, with issues")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__, only_packages="zlib1g"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.debug("Fired: {}".format(t.fired))
        self.assertEqual(len(t.fired), 2)

        logger.info("Specific pkg, with issues")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__, only_packages="util-linux"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.debug("Fired: {}".format(t.fired))
        self.assertGreaterEqual(len(t.fired), 1)

        logger.info("Specific pkg, no issues")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__, only_packages="findutil-notfound"
        )
        db = get_thread_scoped_session()
        db.refresh(self.test_image)
        test_context = gate.prepare_context(self.test_image, test_context)
        t.evaluate(self.test_image, test_context)
        logger.debug("Fired: {}".format(t.fired))
        self.assertEqual(len(t.fired), 0)

        logger.info("Trying default params on all loaded images")
        t, gate, test_context = self.get_initialized_trigger(
            VerifyTrigger.__trigger_name__
        )
        for img_id, meta in list(self.test_env.image_map.items()):
            if img_id == self.test_image.id:
                continue
            t.reset()

            img_obj = db.query(Image).get((img_id, "0"))
            logger.info("Default params check on img: {}".format(img_id))

            test_context = gate.prepare_context(img_obj, test_context)
            t.evaluate(img_obj, test_context)
            logger.info(
                "Image name: {}, id: {}, Fired count: {}\nFired: {}".format(
                    meta.get("name"), img_id, len(t.fired), t.fired
                )
            )
            # self.assertEqual(len(t.fired), 0, 'Found failed verfications on: {}'.format(img_obj.id))

    def test_db_pkg_compare(self):
        """
        Test the pkg metadata diff function specifically.

        :return:
        """
        int_m = int("010755", 8)
        p1 = ImagePackageManifestEntry()
        p1.file_path = "/test1"
        p1.is_config_file = False
        p1.size = 1000
        p1.mode = int_m
        p1.digest = "abc"
        p1.digest_algorithm = "sha256"

        fs_entry = {
            "is_packaged": True,
            "name": "/test1",
            "suid": None,
            "entry_type": "file",
            "linkdst_fullpath": None,
            "mode": int_m,
            "othernames": [],
            "sha256_checksum": "abc",
            "md5_checksum": "def",
            "sha1_checksum": "abcdef",
            "size": 1000,
        }

        # Result == False
        # Basic equal eval
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        p1.digest = None
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest = "abc"

        # Is config file, skip comparison since expected to change
        p1.is_config_file = True
        p1.digest = "blah123"
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.is_config_file = False
        p1.digest = "abc"

        # sha1 diffs
        p1.digest_algorithm = "sha1"
        p1.digest = "abcdef"
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest_algorithm = "sha256"
        p1.digest = "abc"

        # Cannot compare due to missing digest types
        p1.digest_algorithm = "sha1"
        f = fs_entry.pop("sha1_checksum")
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))
        p1.digest_algorithm = "sha256"
        fs_entry["sha1_checksum"] = f

        # Result == Changed

        # Mode diffs
        p1.mode = int_m + 1
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )
        p1.mode = int_m

        # Size diffs
        p1.size = 1001
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )
        p1.size = 1000

        # Sha256 diffs
        p1.digest = "abd"
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )

        # md5 diffs
        p1.digest_algorithm = "md5"
        p1.digest = "blah"
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )

        # sha1 diffs
        p1.digest_algorithm = "sha1"
        p1.digest = "blah"
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )

        p1.digest = "abc"
        p1.digest_algorithm = "sha256"

        # Some weird mode checks to ensure different length mode numbers are ok
        # FS longer than pkg_db, but eq in match
        fs_entry["mode"] = int("060755", 8)
        p1.mode = int("0755", 8)
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # FS longer than pkg_db but not eq
        fs_entry["mode"] = int("060754", 8)
        p1.mode = int("0755", 8)
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )

        # FS shorter than pkg_db and match
        fs_entry["mode"] = int("0755", 8)
        p1.mode = int("060755", 8)
        self.assertFalse(VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry))

        # FS shorter than pkg_db and no match
        fs_entry["mode"] = int("0755", 8)
        p1.mode = int("060754", 8)
        self.assertEqual(
            VerifyTrigger.VerificationStates.changed,
            VerifyTrigger._diff_pkg_meta_and_file(p1, fs_entry),
        )

        # Result == missing

        # Check against no entry
        self.assertEqual(
            VerifyTrigger.VerificationStates.missing,
            VerifyTrigger._diff_pkg_meta_and_file(p1, None),
        )

        # Check against empty entry
        self.assertEqual(
            VerifyTrigger.VerificationStates.missing,
            VerifyTrigger._diff_pkg_meta_and_file(p1, {}),
        )
