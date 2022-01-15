import json

expected_layers = [
    {
        "layer": "d6d1431672e7a9ca504ccd0a169af8dabaafadc070133d36ca854231cba344da",
        "dockerfile_line": "ADD file:df16f0875beb3e2ec874706b70847129bcf4e49337f275e0018b0d9eb46512cf in / ",
        "layer_sizebytes": "73283245",
    },
    {
        "layer": "unknown",
        "dockerfile_line": (
            " LABEL org.label-schema.schema-version=1.0"
            "org.label-schema.name=CentOS "
            "Base Image org.label-schema.vendor=CentOS "
            "org.label-schema.license=GPLv2 "
            "org.label-schema.build-date=20200114 org.opencontainers.image.title=CentOS Base Image org.opencontainers.image.vendor=CentOS org.opencontainers.image.licenses=GPL-2.0-only org.opencontainers.image.created=2020-01-14 00:00:00-08:00"
        ),
        "layer_sizebytes": "0",
    },
    {
        "layer": "unknown",
        "dockerfile_line": ' CMD ["/bin/bash"]',
        "layer_sizebytes": "0",
    },
]


def test_layers(analyzed_data):
    report = analyzed_data()
    data = report["image"]["imagedata"]["analysis_report"]["layer_info"]
    layers = json.loads(data["layers_to_dockerfile"]["base"]["dockerfile_to_layer_map"])
    # This is far from ideal. These assertions should be on separate functions but given the
    # unordered list of dicts, this works for now.
    assert sorted(layers[0]) == sorted(expected_layers[0])
    assert sorted(layers[1]) == sorted(expected_layers[1])
    assert sorted(layers[2]) == sorted(expected_layers[2])
