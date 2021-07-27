import subprocess
import unittest

from anchore_engine.util.apk import compare_versions

enable_training = False


class TestApkVersionHandling(unittest.TestCase):
    versions = [
        ("1", "1", {"lt": False, "gt": False, "eq": True}),
        ("1", "1.0", {"lt": True, "gt": False, "eq": False}),
        ("1.0", "1.0", {"lt": False, "gt": False, "eq": True}),
        (
            "1.0",
            "1.0_alpha",
            {"lt": True, "gt": False, "eq": False},
        ),  # There is a bug in APK here, where it treats comparison of 1.0 vs 1.0_alpha differently than 1.1 vs 1.1_alpha
        ("1.1", "1.1_alpha", {"lt": False, "gt": True, "eq": False}),
        ("1.0", "1.0-r1", {"lt": True, "gt": False, "eq": False}),
        ("1.1", "1.0-r1", {"lt": False, "gt": True, "eq": False}),
        ("1.1", "1.0_p1", {"lt": False, "gt": True, "eq": False}),
        ("1.1", "1.2_alpha", {"lt": True, "gt": False, "eq": False}),
        ("1", "1-r1", {"lt": True, "gt": False, "eq": False}),
        ("1.1", "1-r1", {"lt": False, "gt": True, "eq": False}),
        ("1", "1_p1", {"lt": True, "gt": False, "eq": False}),
        ("1.1", "1_p1", {"lt": False, "gt": True, "eq": False}),
        ("1", "1_alpha", {"lt": False, "gt": True, "eq": False}),
        ("1-r1", "1_p1", {"lt": True, "gt": False, "eq": False}),
        ("1-r1", "1-r2", {"lt": True, "gt": False, "eq": False}),
        ("1_p1", "1", {"lt": False, "gt": True, "eq": False}),
        ("1", "1.0", {"lt": True, "gt": False, "eq": False}),
        ("1.0", "1.0", {"lt": False, "gt": False, "eq": True}),
        ("1", "2", {"lt": True, "gt": False, "eq": False}),
        ("11", "1", {"lt": False, "gt": True, "eq": False}),
        ("1.10.0", "1.2.0", {"lt": False, "gt": True, "eq": False}),
        ("1.1.10", "1.1.4-r1", {"lt": False, "gt": True, "eq": False}),
        ("1.1_blarf", "1.1_alpha", {"lt": False, "gt": True, "eq": False}),
        ("1.1_arghhh", "1.1_p1", {"lt": True, "gt": False, "eq": False}),
        ("1.1_blah", "1.1_alpha", {"lt": False, "gt": True, "eq": False}),
        ("1.1a", "1.1b", {"lt": True, "gt": False, "eq": False}),
        ("1.1b", "1.1a", {"lt": False, "gt": True, "eq": False}),
        ("1.1baa", "1.1b", {"lt": False, "gt": True, "eq": False}),
        ("1.1ba", "1.2", {"lt": True, "gt": False, "eq": False}),
        ("1.1ba", "1.1c", {"lt": True, "gt": False, "eq": False}),
        ("1.0.2k-r0", "1.0.2i-r0", {"lt": False, "gt": True, "eq": False}),
    ]

    ops = {"=": "eq", "<": "lt", ">": "gt", "gt": ">", "lt": "<", "eq": "="}

    def test_version_comparison(self):
        for lval, rval, tests in self.versions:
            for op, result in list(tests.items()):
                print(("{} {} {}, Expected: {}".format(lval, op, rval, result)))
                self.assertEqual(result, compare_versions(lval, op, rval))

    @classmethod
    def setUpClass(cls):
        if enable_training:
            print("Executing result detection using apk from docker.io/alpine:latest")

            container_id = subprocess.check_output(
                ["docker", "run", "-tid", "alpine", "tail", "-f", "/dev/null"]
            )
            container_id = container_id.strip()
            try:
                for lval, rval, tests in cls.versions:
                    out = subprocess.check_output(
                        [
                            "docker",
                            "exec",
                            container_id,
                            "apk",
                            "version",
                            lval,
                            rval,
                            "-t",
                        ]
                    )
                    out_op = out.strip()
                    print(("From apk test, got {} {} = {}".format(lval, rval, out_op)))
                    for op, result in list(tests.items()):
                        if op == cls.ops[out_op]:
                            tests[op] = True
                        else:
                            tests[op] = False
                print(
                    (
                        "Detected truth values for comparison are: {}".format(
                            cls.versions
                        )
                    )
                )
            finally:
                subprocess.check_call(["docker", "rm", "-f", container_id])
