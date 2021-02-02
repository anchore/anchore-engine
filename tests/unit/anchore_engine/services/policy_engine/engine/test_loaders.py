from anchore_engine.db import Image
from anchore_engine.services.policy_engine.engine.loaders import ImageLoader


def get_image():
    img = Image()
    img.user_id = "unit_test"
    img.id = "da28a15dbf563fbc5a486f622b44970ee1bf10f48013bab640f403b06b278543"
    return img


class TestLoadingJavaCPEs:

    ANALYSIS_DATA = {
        "package_list": {
            "pkgs.java": {
                "base": {
                    "/usr/lib/jvm/java-1.8-openjdk/jre/lib/ext/zipfs.jar": '{"cpes": ["cpe:2.3:a:zipfs:zipfs:1.8.0_212:*:*:*:*:java:*:*","cpe:2.3:a:zipfs:zipfs:1.8.0_212:*:*:*:*:maven:*:*","cpe:2.3:a:*:zipfs:1.8.0_212:*:*:*:*:java:*:*","cpe:2.3:a:*:zipfs:1.8.0_212:*:*:*:*:maven:*:*","cpe:2.3:a:zipfs:zipfs:1.8.0_212:*:*:*:*:*:*:*","cpe:2.3:a:*:zipfs:1.8.0_212:*:*:*:*:*:*:*"],"implementation-version": "1.8.0_212","location": "/usr/lib/jvm/java-1.8-openjdk/jre/lib/ext/zipfs.jar","maven-version": "N/A","origin": "Oracle Corporation","name": "zipfs","specification-version": "1.8","type": "java-jar"}'
                }
            }
        }
    }

    def test_extract_java_syft_cpes_returns_cpes(self):
        cpes = ImageLoader(self.ANALYSIS_DATA).extract_syft_cpes(
            {},
            self.ANALYSIS_DATA["package_list"]["pkgs.java"]["base"],
            get_image(),
            "java",
        )
        assert cpes is not None

    def test_fuzzy_java_cpes_returns_cpes(self):
        fuzzy_cpes = ImageLoader(self.ANALYSIS_DATA).get_fuzzy_java_cpes(
            self.ANALYSIS_DATA, {}, get_image()
        )
        assert fuzzy_cpes is not None


class TestLoadingPythonCPEs:

    ANALYSIS_DATA = {
        "package_list": {
            "pkgs.python": {
                "base": {
                    "/usr/local/lib/python3.9/site-packages/wheel": '{"cpes":["cpe:2.3:a:*:wheel:0.36.1:*:*:*:*:*:*:*","cpe:2.3:a:*:wheel:0.36.1:*:*:*:*:python:*:*","cpe:2.3:a:wheel:wheel:0.36.1:*:*:*:*:*:*:*","cpe:2.3:a:wheel:wheel:0.36.1:*:*:*:*:python:*:*","cpe:2.3:a:python-wheel:wheel:0.36.1:*:*:*:*:*:*:*","cpe:2.3:a:python-wheel:wheel:0.36.1:*:*:*:*:python:*:*"],"license":"MIT","licenses":["MIT"],"location":"/usr/local/lib/python3.9/site-packages","origin":"Daniel Holth <dholth@fastmail.fm>","name":"wheel","type":"PYTHON","version":"0.36.1"}'
                }
            }
        }
    }

    def test_extract_python_syft_cpes_returns_cpes(self):
        cpes = ImageLoader(self.ANALYSIS_DATA).extract_syft_cpes(
            {},
            self.ANALYSIS_DATA["package_list"]["pkgs.python"]["base"],
            get_image(),
            "python",
        )
        assert cpes is not None

    def test_fuzzy_python_cpes_returns_cpes(self):
        fuzzy_cpes = ImageLoader(self.ANALYSIS_DATA).get_fuzzy_python_cpes(
            self.ANALYSIS_DATA, {}, get_image()
        )
        assert fuzzy_cpes is not None


class TestLoadingGemsCPEs:

    ANALYSIS_DATA = {
        "package_list": {
            "pkgs.gems": {
                "base": {
                    "/usr/lib/ruby/gems/2.7.0/specifications/default/zlib-1.1.0.gemspec": '{"cpes":["cpe:2.3:a:*:zlib:1.1.0:*:*:*:*:*:*:*"],"license":"BSD-2-Clause","licenses":["BSD-2-Clause"],"location":"/usr/lib/ruby/gems/2.7.0/specifications/default/zlib-1.1.0.gemspec","origin":"Yukihiro Matsumoto,UENO Katsuhiro","name":"zlib","type":"GEM","versions":["1.1.0"]}'
                }
            }
        }
    }

    def test_extract_gems_syft_cpes_returns_cpes(self):
        cpes = ImageLoader(self.ANALYSIS_DATA).extract_syft_cpes(
            {},
            self.ANALYSIS_DATA["package_list"]["pkgs.gems"]["base"],
            get_image(),
            "gem",
        )
        assert cpes is not None

    def test_fuzzy_gem_cpes_returns_cpes(self):
        fuzzy_cpes = ImageLoader(self.ANALYSIS_DATA).get_fuzzy_gem_cpes(
            self.ANALYSIS_DATA, {}, get_image()
        )
        assert fuzzy_cpes is not None


class TestLoadingNpmsCPEs:

    ANALYSIS_DATA = {
        "package_list": {
            "pkgs.npms": {
                "base": {
                    "/usr/lib/node_modules/npm/node_modules/yargs-parser/package.jsonl": '{"cpes":["cpe:2.3:a:*:yargs-parser:9.0.2:*:*:*:*:*:*:*"],"license":"ISC","licenses":["ISC"],"location":"/usr/lib/node_modules/npm/node_modules/yargs-parser/package.json","origin":"Ben Coe <ben@npmjs.com>","name":"yargs-parser","type":"NPM","versions":["9.0.2"]}'
                }
            }
        }
    }

    def test_extract_npms_syft_cpes_returns_cpes(self):
        cpes = ImageLoader(self.ANALYSIS_DATA).extract_syft_cpes(
            {},
            self.ANALYSIS_DATA["package_list"]["pkgs.npms"]["base"],
            get_image(),
            "npm",
        )
        assert cpes is not None

    def test_fuzzy_npm_cpes_returns_cpes(self):
        fuzzy_cpes = ImageLoader(self.ANALYSIS_DATA).get_fuzzy_npm_cpes(
            self.ANALYSIS_DATA, {}, get_image()
        )
        assert fuzzy_cpes is not None
