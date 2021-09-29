import pytest

from anchore_engine.util.cpe_generators import (
    generate_fuzzy_cpes,
    generate_fuzzy_go_cpes,
    generate_gem_products,
    generate_java_cpes,
    generate_npm_products,
    generate_products,
    generate_python_products,
    generate_simple_cpe,
)


@pytest.mark.parametrize(
    "name, expected_list, generator_function",
    [
        pytest.param("gem1", ["gem1"], generate_gem_products, id="gem-simple"),
        pytest.param(
            "cremefraiche",
            ["creme_fraishe", "cremefraiche"],
            generate_gem_products,
            id="gem-matches-inclusion-list",
        ),
        pytest.param("npm1", ["npm1"], generate_gem_products, id="npm-simple"),
        pytest.param(
            "hapi",
            ["hapi", "hapi_server_framework"],
            generate_npm_products,
            id="npm-matches-inclusion-list",
        ),
        pytest.param("python1", ["python1"], generate_gem_products, id="python-simple"),
        pytest.param(
            "python-rrdtool",
            ["python-rrdtool", "rrdtool"],
            generate_python_products,
            id="python-matches-inclusion-list",
        ),
    ],
)
def test_generate_product_functions(name, expected_list, generator_function):
    assert generator_function(name).sort() == expected_list.sort()


@pytest.mark.parametrize(
    "name, package_type, expected_list",
    [
        pytest.param("gem1", "gem", ["gem1"], id="gem-simple"),
        pytest.param(
            "cremefraiche",
            "gem",
            ["creme_fraishe", "cremefraiche"],
            id="gem-matches-inclusion-list",
        ),
        pytest.param("npm1", "npm", ["npm1"], id="npm-simple"),
        pytest.param(
            "hapi",
            "npm",
            ["hapi", "hapi_server_framework"],
            id="npm-matches-inclusion-list",
        ),
        pytest.param("python1", "python", ["python1"], id="python-simple"),
        pytest.param(
            "python-rrdtool",
            "python",
            ["python-rrdtool", "rrdtool"],
            id="python-matches-inclusion-list",
        ),
        pytest.param(
            "foobar",
            "unknownpackagetype",
            ["foobar"],
            id="unknown-package-type",
        ),
    ],
)
def test_generate_products(name, package_type, expected_list):
    assert generate_products(name, package_type).sort() == expected_list.sort()


@pytest.mark.parametrize(
    "name, version, cpe",
    [("product", "version", "cpe:2.3:a:-:product:version:*:*:*:*:*:*:*")],
)
def test_simple_cpe_generation(name, version, cpe):
    assert generate_simple_cpe(name, version) == cpe


@pytest.mark.parametrize(
    "name, version, cpes",
    [
        ("product", "version", ["cpe:2.3:-:product:version:*:*:*:*:*:*:*"]),
        (
            "product",
            "v3.1.0",
            [
                "cpe:2.3:-:product:v3.1.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:product:3.1.0:*:*:*:*:*:*:*",
            ],
        ),
    ],
)
def test_golang_cpe_generation(name, version, cpes):
    assert generate_fuzzy_go_cpes(name, version).sort() == cpes.sort()


@pytest.mark.parametrize(
    "content_dict, cpes",
    [
        pytest.param(
            {
                "package": "javapkg",
                "version": "1.2.3-r0",
                "implementation-version": "1.2.3",
                "specification-version": "1.2.5",
                "maven-version": "2.0.0",
            },
            [
                "cpe:2.3:-:javapkg:1.3.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:1.2.3-r0:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:1.2.3:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:2.0.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:1.2.3-r0:*:*:*:*:*:*:*",
            ],
            id="multi-version-simple-name",
        ),
        pytest.param(
            {
                "package": "javapkg",
                "version": "1.2.3",
            },
            [
                "cpe:2.3:-:javapkg:1.2.3:*:*:*:*:*:*:*",
            ],
            id="simple-version-simple-name",
        ),
        pytest.param(
            {
                "package": "javapkg-1.3.0",
                "version": "1.2.3",
            },
            [
                "cpe:2.3:-:javapkg:1.3.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:1.2.3:*:*:*:*:*:*:*",
            ],
            id="version-name",
        ),
        pytest.param(
            {
                "package": "javapkg-core",
                "version": "1.2.3",
            },
            [
                "cpe:2.3:-:javapkg-core:1.2.3:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg:1.2.3:*:*:*:*:*:*:*",
            ],
            id="compound-name",
        ),
        pytest.param(
            {
                "package": "javapkg-alpha-core",
                "version": "1.2.3",
            },
            [
                "cpe:2.3:-:javapkg-alpha-core:1.2.3:*:*:*:*:*:*:*",
                "cpe:2.3:-:javapkg-alpha:1.2.3:*:*:*:*:*:*:*",
            ],
            id="compound-multi-section-name",
        ),
    ],
)
def test_java_cpe_generation(content_dict, cpes):
    assert generate_java_cpes(content_dict).sort() == cpes.sort()


@pytest.mark.parametrize(
    "name, version, package_type, cpes",
    [
        pytest.param(
            "gem1",
            "1.0.0",
            "gem",
            ["cpe:2.3:-:gem1:1.1.0:*:*:*:*:*:*:*"],
            id="gem-simple",
        ),
        pytest.param(
            "cremefraiche",
            "1.0.0",
            "gem",
            [
                "cpe:2.3:-:creme_fraishe:1.0.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:cremefraishe:1.0.0:*:*:*:*:*:*:*",
            ],
            id="gem-matches-inclusion-list",
        ),
        pytest.param(
            "hapi",
            "1.0.0",
            "npm",
            [
                "cpe:2.3:-:hapi:1.0.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:hapi_server_framework:1.0.0:*:*:*:*:*:*:*",
            ],
            id="npm-matches-inclusion-list",
        ),
        pytest.param(
            "npm1",
            "1.0.0",
            "npm",
            [
                "cpe:2.3:-:npm1:1.0.0:*:*:*:*:*:*:*",
            ],
            id="npm-simple",
        ),
        pytest.param(
            "pythontool",
            "1.0.0",
            "python",
            [
                "cpe:2.3:-:pythontool:1.0.0:*:*:*:*:*:*:*",
            ],
            id="python-simple",
        ),
        pytest.param(
            "python-rrdtool",
            "1.0.0",
            "python",
            [
                "cpe:2.3:-:python-rrdtool:1.0.0:*:*:*:*:*:*:*",
                "cpe:2.3:-:rrdtool:1.0.0:*:*:*:*:*:*:*",
            ],
            id="python-matches-inclusion-list",
        ),
    ],
)
def test_generate_fuzzy_cpes(name, version, package_type, cpes):
    assert generate_fuzzy_cpes(name, version, package_type).sort() == cpes.sort()
