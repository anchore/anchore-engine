import pytest


class TestDockerData:
    def test_architecture(self, analyzed_data):
        data = analyzed_data()
        report = data["image"]["imagedata"]["image_report"]["docker_data"]
        assert report["Architecture"] == "arm64"

    def test_repo_digests(self, analyzed_data):
        data = analyzed_data()
        report = data["image"]["imagedata"]["image_report"]["docker_data"]
        assert report["RepoDigests"] == [
            "docker.io/centos@sha256:85313b812ad747dd19cf18078795b576cc4ae9cd2ca2ccccd7b5c12722b2effd"
        ]

    def test_repo_tags(self, analyzed_data):
        data = analyzed_data()
        report = data["image"]["imagedata"]["image_report"]["docker_data"]
        assert report["RepoTags"] == ["docker.io/centos:centos8"]


@pytest.fixture
def docker_history(analyzed_data):
    data = analyzed_data()
    history = data["image"]["imagedata"]["image_report"]["docker_history"]
    return [i for i in sorted(history, key=lambda i: i.get("Created"))]


class TestDockerHistory:
    """
    Sample Docker History that these tests work with:

    [{'Comment': '',
      'Created': '2020-01-15T01:39:44.178897087Z',
      'CreatedBy': '/bin/sh -c #(nop) ADD '
                   'file:df16f0875beb3e2ec874706b70847129bcf4e49337f275e0018b0d9eb46512cf '
                   'in / ',
      'Id': 'sha256:d6d1431672e7a9ca504ccd0a169af8dabaafadc070133d36ca854231cba344da',
      'Size': 73283245,
      'Tags': []},
     {'Comment': '',
      'Created': '2020-01-17T23:39:30.073835894Z',
      'CreatedBy': '/bin/sh -c #(nop)  LABEL org.label-schema.schema-version=1.0 '
                   'org.label-schema.name=CentOS Base Image '
                   'org.label-schema.vendor=CentOS org.label-schema.license=GPLv2 '
                   'org.label-schema.build-date=20200114 '
                   'org.opencontainers.image.title=CentOS Base Image '
                   'org.opencontainers.image.vendor=CentOS '
                   'org.opencontainers.image.licenses=GPL-2.0-only '
                   'org.opencontainers.image.created=2020-01-14 00:00:00-08:00',
      'Id': '<missing>',
      'Size': 0,
      'Tags': []},
     {'Comment': '',
      'Created': '2020-01-17T23:39:30.609540194Z',
      'CreatedBy': '/bin/sh -c #(nop)  CMD ["/bin/bash"]',
      'Id': '<missing>',
      'Size': 0,
      'Tags': []}]
    """

    def test_length_of_items(self, docker_history):
        assert len(docker_history) == 3

    def test_no_comments(self, docker_history):
        # This is hard because can't mix parametrize and fixtures
        assert all(i["Comment"] == "" for i in docker_history)

    def test_no_tags(self, docker_history):
        assert all(i["Tags"] == [] for i in docker_history)

    # these tests are oddly named, because again, can't really do parametrize
    # with fixtures in pytest :(
    def test_history_item_0(self, docker_history):
        item = docker_history[0]
        assert item["Created"] == "2020-01-15T01:39:44.178897087Z"
        assert item["CreatedBy"] == (
            "/bin/sh -c #(nop) "
            "ADD file:df16f0875beb3e2ec874706b70847129bcf4e49337f275e0018b0d9eb46512cf in / "
        )
        assert (
            item["Id"]
            == "sha256:d6d1431672e7a9ca504ccd0a169af8dabaafadc070133d36ca854231cba344da"
        )
        assert item["Size"] == 73283245

    def test_history_item_1(self, docker_history):
        item = docker_history[1]
        assert item["Created"] == "2020-01-17T23:39:30.073835894Z"
        assert item["CreatedBy"] == (
            "/bin/sh -c #(nop)  LABEL "
            "org.label-schema.schema-version=1.0 "
            "org.label-schema.name=CentOS Base Image "
            "org.label-schema.vendor=CentOS "
            "org.label-schema.license=GPLv2 "
            "org.label-schema.build-date=20200114 "
            "org.opencontainers.image.title=CentOS Base Image "
            "org.opencontainers.image.vendor=CentOS "
            "org.opencontainers.image.licenses=GPL-2.0-only "
            "org.opencontainers.image.created=2020-01-14 00:00:00-08:00"
        )
        assert item["Id"] == "<missing>"
        assert item["Size"] == 0

    def test_history_item_2(self, docker_history):
        item = docker_history[2]
        assert item["Created"] == "2020-01-17T23:39:30.609540194Z"
        assert item["CreatedBy"] == '/bin/sh -c #(nop)  CMD ["/bin/bash"]'
        assert item["Id"] == "<missing>"
        assert item["Size"] == 0


def test_layers(analyzed_data):
    data = analyzed_data()
    report = data["image"]["imagedata"]["image_report"]["layers"]
    assert report == [
        "sha256:d6d1431672e7a9ca504ccd0a169af8dabaafadc070133d36ca854231cba344da"
    ]


def test_family_tree(analyzed_data):
    data = analyzed_data()
    report = data["image"]["imagedata"]["image_report"]["familytree"]
    assert report == [
        "sha256:d6d1431672e7a9ca504ccd0a169af8dabaafadc070133d36ca854231cba344da"
    ]


def test_meta(analyzed_data):
    data = analyzed_data()
    report = data["image"]["imagedata"]["image_report"]["meta"]
    assert report == {
        "humanname": "docker.io/centos:centos8",
        "imageId": "XXX",
        "imagename": "XXX",
        "parentId": "",
        "shortId": "XXX",
        "shortname": "XXX",
        "shortparentId": "",
        "sizebytes": 297338880,
        "usertype": None,
    }


def test_dockerfile_mode(analyzed_data):
    data = analyzed_data()
    actual = data["image"]["imagedata"]["image_report"]["dockerfile_mode"]
    assert actual == "Guessed"


def test_docker_file_contents(analyzed_data):
    data = analyzed_data()
    report = data["image"]["imagedata"]["image_report"]["dockerfile_contents"]
    assert report == (
        "FROM scratch\n"
        "ADD file:df16f0875beb3e2ec874706b70847129bcf4e49337f275e0018b0d9eb46512cf in / \n"
        "LABEL org.label-schema.schema-version=1.0 org.label-schema.name=CentOS "
        "Base Image org.label-schema.vendor=CentOS org.label-schema.license=GPLv2 "
        "org.label-schema.build-date=20200114 org.opencontainers.image.title=CentOS "
        "Base Image org.opencontainers.image.vendor=CentOS "
        "org.opencontainers.image.licenses=GPL-2.0-only "
        'org.opencontainers.image.created=2020-01-14 00:00:00-08:00\nCMD ["/bin/bash"]\n'
    )
