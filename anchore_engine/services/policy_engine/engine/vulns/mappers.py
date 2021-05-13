import datetime
import json
from collections import defaultdict
from anchore_engine.db import Image, ImageCpe, ImagePackage
from typing import List, Dict
import uuid
from anchore_engine.subsys import logger as log
from anchore_engine.services.policy_engine.api.models import (
    VulnerabilityMatch,
    Artifact,
    Vulnerability,
    CvssCombined,
    CvssScore,
    Match,
    FixedArtifact,
)


class DistroMapper:
    engine_distro = None
    grype_os = None
    grype_like_os = None

    @staticmethod
    def for_engine(distro: str):
        return ENGINE_DISTRO_MAPPERS.get(distro)

    @staticmethod
    def for_grype(distro: str):
        return GRYPE_DISTRO_MAPPERS.get(distro)

    def to_grype_distro(self, version):
        return {
            "name": self.grype_os,
            "version": version,
            "idLike": self.grype_like_os,
        }


class RhelMapper(DistroMapper):
    engine_distro = "rhel"
    grype_os = "redhat"
    grype_like_os = "fedora"


class DebianMapper(DistroMapper):
    engine_distro = "debian"
    grype_os = "debian"
    grype_like_os = "debian"


class UbuntuMapper(DistroMapper):
    engine_distro = "ubuntu"
    grype_os = "ubuntu"
    grype_like_os = "debian"


class AlpineMapper(DistroMapper):
    engine_distro = "alpine"
    grype_os = "alpine"
    grype_like_os = "alpine"


class CentOSMapper(DistroMapper):
    engine_distro = "centos"
    grype_os = "centos"
    grype_like_os = "fedora"  # TODO check with toolbox


class OracleLinuxMapper(DistroMapper):
    engine_distro = "ol"
    engine_like_distro = "fedora"
    grype_os = "oraclelinux"
    grype_like_os = "fedora"  # TODO check with toolbox


class AmazonLinuxMapper(DistroMapper):
    engine_distro = "amzn"
    engine_like_distro = "fedora"
    grype_os = "amazonlinux"
    grype_like_os = "fedora"  # TODO check with toolbox


class PackageMapper:
    engine_type = None
    grype_type = None

    @staticmethod
    def for_engine(pkg_type: str):
        return ENGINE_PACKAGE_MAPPERS.get(pkg_type)

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = {
            "id": str(uuid.uuid4()),
            "name": image_package.name,
            "version": image_package.fullversion,
            "type": self.grype_type,
            "language": "",
            "locations": [
                {
                    "path": image_package.pkg_path,
                }
            ],
            # TODO check with alex on how to format source package and version. Override this method in individual mappers
        }

        return artifact

    def to_engine_vulnerability_match(self, item, now: datetime.datetime):
        artifact = item.get("artifact")
        vuln = item.get("vulnerability")

        vuln_id = vuln.get("id")
        fix_ver = vuln.get("fixedInVersion")
        if fix_ver:
            fix_observed_at = now
        else:
            fix_ver = "None"  # barf needed for policy evals and external api
            fix_observed_at = None

        engine_nvd_scores = []
        engine_vendor_scores = []  # TODO replace with grype data when available

        grype_cvss_v2 = vuln.get("cvssV2")
        grype_cvss_v3 = vuln.get("cvssV3")

        # TODO replace this with grype data
        if grype_cvss_v2 or grype_cvss_v3:
            engine_score = CvssCombined(id=vuln_id)
            engine_nvd_scores.append(engine_score)

            if grype_cvss_v2:
                engine_score.cvss_v2 = CvssScore(
                    base_score=grype_cvss_v2.get("baseScore", -1.0),
                    exploitability_score=grype_cvss_v2.get("exploitabilityScore", -1.0),
                    impact_score=grype_cvss_v2.get("impactScore", -1.0),
                )

            if grype_cvss_v3:
                engine_score.cvss_v3 = CvssScore(
                    base_score=grype_cvss_v3.get("baseScore", -1.0),
                    exploitability_score=grype_cvss_v3.get("exploitabilityScore", -1.0),
                    impact_score=grype_cvss_v3.get("impactScore", -1.0),
                )

        pkg_name = artifact.get("name")
        pkg_version = artifact.get("version")
        pkg_path = (
            artifact.get("locations")[0].get("path")
            if artifact.get("locations")
            else "NA"
        )

        search_key = item.get("matchDetails").get("searchKey")

        # TODO replace with grype data when available
        is_legacy = False
        if "distro" in search_key:
            distro = search_key.get("distro")
            feed_group = self.get_feed_group_from_grype_match_distro(distro)
            feed = "vulnerabilities"
        elif vuln_id.startswith("GHSA"):
            feed = "vulnerabilities"
            feed_group = "github:{}".format(self.engine_type)
        elif vuln_id.startswith("VULNDB"):  # this is absolutely WRONG!!!
            feed = "vulndb"
            feed_group = "vulndb:vulnerabilities"
        else:
            feed = "nvdv2"
            feed_group = "nvdv2:cves"

        vuln_match = VulnerabilityMatch(
            vulnerability=Vulnerability(
                vulnerability_id=vuln_id,
                description="NA",
                severity=vuln.get("severity"),
                link=vuln.get("links")[0] if vuln.get("links") else None,
                feed=feed,
                feed_group=feed_group,
                cvss_scores_nvd=engine_nvd_scores,
                cvss_scores_vendor=[],
                created_at=now,  # TODO replace with grype data when available
                last_modified=now,  # TODO replace with grype data when available
            ),
            artifact=Artifact(
                name=pkg_name,
                version=pkg_version,
                pkg_type=self.engine_type,
                pkg_path=pkg_path,
                cpe="None",  # TODO replace with grype data when available
                cpe23="None",  # TODO replace with grype data when available
            ),
            fixes=[
                FixedArtifact(
                    version=fix_ver,
                    wont_fix=False,  # TODO replace with grype data when available
                    observed_at=fix_observed_at,
                )
            ],
            match=Match(detected_at=now),
        )

        return vuln_match

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        return None


class RpmMapper(PackageMapper):
    engine_type = "rpm"
    grype_type = "rpm"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = super().to_grype_artifact(image_package, location_cpes_dict)
        if image_package.normalized_src_pkg != "N/A":
            artifact["metadata"] = {"sourceRpm": image_package.normalized_src_pkg}
        return artifact

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        """
        TODO This tries to map the feed group from grype match. Replace it with feed group from grype
        {
         "type": "redhat",
         "version": "8.3"
        }
        """
        distro = distro_dict.get("type")
        if distro.lower() in [RhelMapper.grype_os, CentOSMapper.grype_os]:
            distro = RhelMapper.engine_distro
        elif distro.lower() == OracleLinuxMapper.grype_os:
            distro = OracleLinuxMapper.engine_distro
        elif distro.lower() == AmazonLinuxMapper.grype_os:
            distro = AmazonLinuxMapper.engine_distro
        else:
            raise ValueError(
                "Expected distro to be in {} but found {}".format(
                    [
                        RhelMapper.grype_os,
                        CentOSMapper.grype_os,
                        OracleLinuxMapper.grype_os,
                        AmazonLinuxMapper.grype_os,
                    ],
                    distro,
                )
            )

        version = distro_dict.get("version").split(".", 1)[0]

        return "{}:{}".format(distro, version)


class DpkgMapper(PackageMapper):
    engine_type = "dpkg"
    grype_type = "deb"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = super().to_grype_artifact(image_package, location_cpes_dict)
        # TODO
        # if image_package.normalized_src_pkg != "N/A":
        #     artifact["metadata"] = {"sourceRpm": image_package.normalized_src_pkg}
        return artifact

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        """
        {
         "type": "ubuntu",
         "version": "8.3"
        }
        """
        distro = distro_dict.get("type")
        if distro.lower() == UbuntuMapper.grype_os:
            distro = UbuntuMapper.engine_distro
        elif distro.lower() == DebianMapper.grype_os:
            distro = DebianMapper.engine_distro
        else:
            raise ValueError(
                "Expected distro to be {} or {} but found {}".format(
                    UbuntuMapper.grype_os, DebianMapper.grype_os, distro
                )
            )

        version = distro_dict.get("version")

        return "{}:{}".format(distro, version)


class ApkgMapper(PackageMapper):
    engine_type = "APKG"
    grype_type = "apk"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = super().to_grype_artifact(image_package, location_cpes_dict)
        # TODO
        # if image_package.normalized_src_pkg != "N/A":
        #     artifact["metadata"] = {"sourceRpm": image_package.normalized_src_pkg}
        return artifact

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        """
        {
         "type": "redhat",
         "version": "8.3"
        }
        """
        distro = distro_dict.get("type")
        if distro.lower() == AlpineMapper.grype_os:
            distro = AlpineMapper.engine_distro
        else:
            raise ValueError(
                "Expected distro to be {} but found {}".format(
                    AlpineMapper.grype_os, distro
                )
            )

        version = distro_dict.get("version").split(".", 1)[0]

        return "{}:{}".format(distro, version)


class CPEMapper(PackageMapper):
    engine_type = None
    grype_type = None

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = super().to_grype_artifact(image_package)
        artifact["cpes"] = [
            # cpe : 2.3 : part : vendor : product : version : update : edition : language : sw_edition : target_sw : target_hw : other
            "cpe:2.3:{}".format(
                ":".join(
                    [
                        item.cpetype,  # part
                        item.vendor,  # vendor
                        item.name,  # product
                        item.version,  # version
                        item.update,  # update
                        item.meta,  # edition
                        "-",  # language
                        "-",  # sw_edition
                        "-",  # target_sw
                        "-",  # target_hw
                        "-",  # other
                    ]
                )
            )
            for item in location_cpes_dict.get(image_package.pkg_path)
        ]

        return artifact


class PythonMapper(CPEMapper):
    engine_type = "python"
    grype_type = "python"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        return super().to_grype_artifact(image_package, location_cpes_dict)


class JavaMapper(CPEMapper):
    engine_type = "java"
    grype_type = "java-archive"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        return super().to_grype_artifact(image_package, location_cpes_dict)


class NpmMapper(CPEMapper):
    engine_type = "npm"
    grype_type = "npm"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        return super().to_grype_artifact(image_package, location_cpes_dict)


class GemMapper(CPEMapper):
    engine_type = "gem"
    grype_type = "gem"

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        return super().to_grype_artifact(image_package, location_cpes_dict)


# key is the engine distro
ENGINE_DISTRO_MAPPERS = {
    "rhel": RhelMapper,
    "debian": DebianMapper,
    "ubuntu": UbuntuMapper,
    "alpine": AlpineMapper,
    "ol": OracleLinuxMapper,
    "amzn": AmazonLinuxMapper,
    "centos": CentOSMapper,
}

# key is the grype distro
GRYPE_DISTRO_MAPPERS = {
    "redhat": RhelMapper,
    "ubuntu": UbuntuMapper,
    "debian": DebianMapper,
    "alpine": AlpineMapper,
    "oraclelinux": OracleLinuxMapper,
    "amazonlinux": AmazonLinuxMapper,
    "centos": CentOSMapper,
}

ENGINE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper,
    "dpkg": DpkgMapper,
    "APKG": ApkgMapper,
    "python": PythonMapper,
    "npm": NpmMapper,
    "gem": GemMapper,
    "java": JavaMapper,
}

GRYPE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper,
    "deb": DpkgMapper,
    "apk": ApkgMapper,
    "python": PythonMapper,
    "npm": NpmMapper,
    "gem": GemMapper,
    "java-archive": JavaMapper,
    "java-plugin": JavaMapper,
}


class EngineGrypeMapper:
    def to_grype_sbom(
        self,
        image: Image,
        image_packages: List[ImagePackage],
        image_cpes: List[ImageCpe],
    ):
        """
        Generate grype sbom from ImagePackage artifacts
        """
        distro_mapper_class = ENGINE_DISTRO_MAPPERS.get(image.distro_name)
        if not distro_mapper_class:
            log.error(
                "No distro mapper found for %s. Cannot generate sbom", image.distro_name
            )
            raise ValueError(
                "No distro mapper found for {}. Cannot generate sbom".format(
                    image.distro_name
                )
            )
        distro_mapper = distro_mapper_class()

        # map the package (location) to its list of cpes
        location_cpes_dict = defaultdict(list)
        for image_cpe in image_cpes:
            location_cpes_dict[image_cpe.pkg_path].append(image_cpe)

        # create the sbom
        sbom = dict()

        sbom["distro"] = distro_mapper.to_grype_distro(image.distro_version)
        sbom["source"] = {
            "type": "image",
            "target": {
                "scope": "Squashed",
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            },
        }

        artifacts = []
        sbom["artifacts"] = artifacts

        for pkg in image_packages:
            pkg_mapper_class = PackageMapper.for_engine(pkg.pkg_type)
            if not pkg_mapper_class:
                log.warn(
                    "No package mapper found for engine package type %s", pkg.pkg_type
                )
            pkg_mapper = pkg_mapper_class()
            artifacts.append(pkg_mapper.to_grype_artifact(pkg, location_cpes_dict))

        # log.debug("image sbom: {}".format(json.dumps(sbom, indent=2)))

        return sbom

    def to_engine_vulnerabilities(self, grype_response):
        """
        Transform grype results into engine vulnerabilities
        """
        # TODO super duper hacky to fit into existing model

        now = datetime.datetime.utcnow()
        matches = grype_response.get("matches", [])

        results = []

        for item in matches:
            artifact = item.get("artifact")

            pkg_mapper_class = GRYPE_PACKAGE_MAPPERS.get(artifact.get("type"))
            if not pkg_mapper_class:
                log.warn(
                    "No package mapper found for grype package type %s",
                    artifact.get("type"),
                )
            pkg_mapper = pkg_mapper_class()

            results.append(pkg_mapper.to_engine_vulnerability_match(item, now))

        return results


# if __name__ == "__main__":
#     a = ImagePackage()
#     a.name = "foo"
#     a.fullversion = "foo"
#     a.pkg_path = "foo"
#     a.normalized_src_pkg = "foo"
#     b = RpmPackageMapper().to_grype(a)
#     print(b)
