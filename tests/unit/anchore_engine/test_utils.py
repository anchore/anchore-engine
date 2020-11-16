from anchore_engine.utils import parse_dockerimage_string
from anchore_engine.subsys import logger

logger.enable_test_logging(level="INFO")


def test_parse_dockerimage_string():
    tests = [
        (
            "docker.io/library/nginx",
            {
                "digest": None,
                "fulldigest": None,
                "fulltag": "docker.io/library/nginx:latest",
                "host": "docker.io",
                "imageId": None,
                "port": None,
                "pullstring": "docker.io/library/nginx:latest",
                "registry": "docker.io",
                "repo": "library/nginx",
                "repotag": "library/nginx:latest",
                "tag": "latest",
            },
        ),
        (
            "docker.io/nginx",
            {
                "digest": None,
                "fulldigest": None,
                "fulltag": "docker.io/nginx:latest",
                "host": "docker.io",
                "imageId": None,
                "port": None,
                "pullstring": "docker.io/nginx:latest",
                "registry": "docker.io",
                "repo": "nginx",
                "repotag": "nginx:latest",
                "tag": "latest",
            },
        ),
        (
            "nginx",
            {
                "digest": None,
                "fulldigest": None,
                "fulltag": "docker.io/nginx:latest",
                "host": "docker.io",
                "imageId": None,
                "port": None,
                "pullstring": "docker.io/nginx:latest",
                "registry": "docker.io",
                "repo": "nginx",
                "repotag": "nginx:latest",
                "tag": "latest",
            },
        ),
        (
            "docker.io/library/nginx@sha256:abcdef123",
            {
                "digest": "sha256:abcdef123",
                "fulldigest": "docker.io/library/nginx@sha256:abcdef123",
                "fulltag": None,
                "host": "docker.io",
                "imageId": None,
                "port": None,
                "pullstring": "docker.io/library/nginx@sha256:abcdef123",
                "registry": "docker.io",
                "repo": "library/nginx",
                "repotag": None,
                "tag": None,
            },
        ),
        (
            "docker.io/nginx@sha256:abcdef123",
            {
                "digest": "sha256:abcdef123",
                "fulldigest": "docker.io/nginx@sha256:abcdef123",
                "fulltag": None,
                "host": "docker.io",
                "imageId": None,
                "port": None,
                "pullstring": "docker.io/nginx@sha256:abcdef123",
                "registry": "docker.io",
                "repo": "nginx",
                "repotag": None,
                "tag": None,
            },
        ),
    ]

    for input, result in tests:
        logger.info("Testing parsing {}".format(input))
        output = parse_dockerimage_string(input)
        try:
            assert output == result
        except:
            logger.error(
                "Failed parsing {} to expected: {}, Got: {}".format(
                    input, result, output
                )
            )
            raise
