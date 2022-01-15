"""
Gate Unit tests
"""
import pytest

from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.policy.gates.image_metadata import (
    ImageMetadataAttributeCheckTrigger,
    ImageMetadataGate,
)
from anchore_engine.subsys import logger
from tests.integration.services.policy_engine.engine.policy.gates import GateUnitTest

logger.enable_test_logging()

test_image = Image()
test_image.distro_name = "debian"
test_image.distro_version = "9"
test_image.like_distro = "debian"
test_image.user_id = "0"
test_image.layers_json = ["sha256:a", "sha256:b", "sha256:c"]
test_image.layer_info_json = ["layer1", "layer2"]
test_image.dockerfile_contents = "FROM SCRATCH\nHEALTHcheck blah\n"
test_image.dockerfile_mode = "Guessed"
test_image.size = 100 * 1024 * 1024
test_image.docker_data_json = {
    "Comment": "",
    "Container": "4e69ef98747345110dc23069be98ff0ae562cc83a187ff1bdd1d2e0048889679",
    "DockerVersion": "17.03.1-ce",
    "Parent": "",
    "Created": "2017-05-15T17:41:29.424239055Z",
    "Config": {
        "Tty": False,
        "Cmd": ["node"],
        "Volumes": None,
        "Domainname": "",
        "WorkingDir": "",
        "Image": "sha256:6f109e97451ad43719c0a1802153811ad2f02d912a1d15a2ed7f0728be3026b6",
        "Hostname": "200591939db7",
        "StdinOnce": False,
        "ArgsEscaped": True,
        "Labels": {},
        "AttachStdin": False,
        "User": "",
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NPM_CONFIG_LOGLEVEL=info",
            "NODE_VERSION=7.10.0",
            "YARN_VERSION=0.24.4",
        ],
        "Entrypoint": False,
        "OnBuild": [],
        "AttachStderr": False,
        "AttachStdout": False,
        "OpenStdin": False,
    },
    "RepoDigests": [
        "node@sha256:ca55f4f5cb68a78c3ad9fe1ee13cba692906ec25dd73782800cbd4ae4b9fac45"
    ],
    "Author": "",
    "GraphDriver": {"Data": None, "Name": "aufs"},
    "Id": "sha256:6c792d9195914c8038f4cabd9356a5af47ead140b87682c8651edd55b010686c",
    "VirtualSize": 665664130,
    "Architecture": "amd64",
    "ContainerConfig": {
        "Tty": False,
        "Cmd": ["/bin/sh", "-c", "#(nop) ", 'CMD ["node"]'],
        "Volumes": None,
        "Domainname": "",
        "WorkingDir": "",
        "Image": "sha256:6f109e97451ad43719c0a1802153811ad2f02d912a1d15a2ed7f0728be3026b6",
        "Hostname": "200591939db7",
        "StdinOnce": False,
        "ArgsEscaped": True,
        "Labels": {},
        "AttachStdin": False,
        "User": "",
        "Env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "NPM_CONFIG_LOGLEVEL=info",
            "NODE_VERSION=7.10.0",
            "YARN_VERSION=0.24.4",
        ],
        "Entrypoint": None,
        "OnBuild": [],
        "AttachStderr": False,
        "AttachStdout": False,
        "OpenStdin": False,
    },
    "RepoTags": ["node:latest"],
    "Os": "linux",
    "RootFS": {
        "Layers": [
            "sha256:8d4d1ab5ff74fc361fb74212fff3b6dc1e6c16d1e1f0e8b44f9a9112b00b564f",
            "sha256:c59fa6cbcbd97c74330d140b99d12098d2d80c77533d35444d311c9393d129ce",
            "sha256:445ed6ee6867fb85175f4c784722576125ea6352219637b792e0bdf3d3357e9c",
            "sha256:e7b0b4cd055a4570908cd908865755362570be3157e5bdb64e93b8a5ca3a1b61",
            "sha256:2607b744b89df8bd9eb04c49319abc672b2cf1479ef63996d33c64033c988293",
            "sha256:0f20784b55ffa7d6d82533f54a0b6476e305a3b578bf9ed681bcb2a4f4f3e9dc",
            "sha256:a8d5a17bf5cccb8f640bf6ab662a7e0881e20f5335c93ec97a6dcd3a6942195b",
            "sha256:3e88edcc5f79b45da734bd31106a71913759a6d8d965dee50fad73bfcf378f26",
        ],
        "Type": "layers",
    },
    "Size": 665664130,
}


@pytest.mark.usefixtures("cls_test_data_env2")
class ImageMetadataGateTest(GateUnitTest):
    gate_clazz = ImageMetadataGate

    def test_imagemetadata_validator(self):
        test = {
            "size": ("100", True),
            "architecture": ("test", True),
            "os_type": ("rhel", True),
            "distro": ("centos", True),
            "distro_version": ("8", True),
            "like_distro": ("rhel", True),
            "layer_count": ("10", True),
            "blah": ("", False),
            "image_size": ("100000", False),
            "layer_size": ("100", False),
        }
        for attr, result in list(test.items()):
            val, expect_ok = result

            try:
                t, gate, test_context = self.get_initialized_trigger(
                    ImageMetadataAttributeCheckTrigger.__trigger_name__,
                    attribute=attr,
                    check="=",
                    value=val,
                )
                if not expect_ok and t:
                    self.assertEqual(expect_ok, bool(t))
            except:
                if not expect_ok:
                    logger.info(
                        (
                            "Caught expected exception on invalid attr name: {}".format(
                                attr
                            )
                        )
                    )
                else:
                    raise

    def test_imagemetadatatrigger_params(self):
        test = {
            "size": str(test_image.size),
            "architecture": "amd64",
            "os_type": "linux",
            "distro": test_image.distro_name,
            "distro_version": test_image.distro_version,
            "like_distro": test_image.like_distro,
            "layer_count": str(len(test_image.layers_json)),
        }
        for val, check in list(test.items()):
            logger.info(("Testing attr {} against {}".format(val, check)))
            t, gate, test_context = self.get_initialized_trigger(
                ImageMetadataAttributeCheckTrigger.__trigger_name__,
                attribute=val,
                check="=",
                value=check,
            )
            test_context = gate.prepare_context(test_image, test_context)
            t.evaluate(test_image, test_context)
            self.assertEqual(len(t.fired), 1)
            logger.info(("Fired: {}".format([x.json() for x in t.fired])))

    def test_imagemetadatatrigger_distro_name(self):
        logger.info("Testing =")
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="=",
            value="debian",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="=",
            value="mandriva",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info("Testing !=")
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="!=",
            value="mandriva",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="!=",
            value="debian",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info("Testing like")
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="like",
            value=".*ebia.*",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="like",
            value=".*entos.*",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info("Testing not_like")
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="not_like",
            value=".*entos.*",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info('Testing "in"')
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="in",
            value=" centos , debian ",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info('Testing "in" --fail')
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="in",
            value=" centos , rhel ",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info('Testing "not_in"')
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="not_in",
            value=" centos , mandriva ",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 1)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))

        logger.info('Testing "not_in" --fail')
        t, gate, test_context = self.get_initialized_trigger(
            ImageMetadataAttributeCheckTrigger.__trigger_name__,
            attribute="distro",
            check="not_in",
            value=" debian , rhel ",
        )
        test_context = gate.prepare_context(test_image, test_context)
        t.evaluate(test_image, test_context)
        self.assertEqual(len(t.fired), 0)
        logger.info(("Fired: {}".format([x.json() for x in t.fired])))
