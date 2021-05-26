import datetime
import uuid
from collections import defaultdict
from typing import List, Dict

from anchore_engine.db import Image, ImageCpe, ImagePackage
from anchore_engine.util.models import (
    VulnerabilityMatch,
    Artifact,
    Vulnerability,
    CvssCombined,
    CvssScore,
    Match,
    FixedArtifact,
)
from anchore_engine.subsys import logger as log


class DistroMapper:
    engine_distro = None
    grype_os = None
    grype_like_os = None

    def __init__(self, engine_distro, grype_os, grype_like_os):
        self.engine_distro = engine_distro
        self.grype_os = grype_os
        self.grype_like_os = grype_like_os

    def to_grype_distro(self, version):
        return {
            "name": self.grype_os,
            "version": version,
            "idLike": self.grype_like_os,
        }


# key is the engine distro
ENGINE_DISTRO_MAPPERS = {
    "rhel": DistroMapper(
        engine_distro="rhel", grype_os="redhat", grype_like_os="fedora"
    ),
    "debian": DistroMapper(
        engine_distro="debian", grype_os="debian", grype_like_os="debian"
    ),
    "ubuntu": DistroMapper(
        engine_distro="ubuntu", grype_os="ubuntu", grype_like_os="debian"
    ),
    "alpine": DistroMapper(
        engine_distro="alpine", grype_os="alpine", grype_like_os="alpine"
    ),
    "ol": DistroMapper(  # TODO check with toolbox
        engine_distro="ol", grype_os="oraclelinux", grype_like_os="fedora"
    ),
    "amzn": DistroMapper(  # TODO check with toolbox
        engine_distro="amzn", grype_os="amazonlinux", grype_like_os="fedora"
    ),
    "centos": DistroMapper(  # TODO check with toolbox
        engine_distro="centos", grype_os="centos", grype_like_os="fedora"
    ),
}

# key is the grype distro
GRYPE_DISTRO_MAPPERS = {
    "redhat": DistroMapper(
        engine_distro="rhel", grype_os="redhat", grype_like_os="fedora"
    ),
    "debian": DistroMapper(
        engine_distro="debian", grype_os="debian", grype_like_os="debian"
    ),
    "ubuntu": DistroMapper(
        engine_distro="ubuntu", grype_os="ubuntu", grype_like_os="debian"
    ),
    "alpine": DistroMapper(
        engine_distro="alpine", grype_os="alpine", grype_like_os="alpine"
    ),
    "oraclelinux": DistroMapper(  # TODO check with toolbox
        engine_distro="ol", grype_os="oraclelinux", grype_like_os="fedora"
    ),
    "amazonlinux": DistroMapper(  # TODO check with toolbox
        engine_distro="amzn", grype_os="amazonlinux", grype_like_os="fedora"
    ),
    "centos": DistroMapper(  # TODO check with toolbox
        engine_distro="centos", grype_os="centos", grype_like_os="fedora"
    ),
}


class PackageMapper:
    def __init__(self, engine_type, grype_type):
        self.engine_type = engine_type
        self.grype_type = grype_type

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
            # Package type specific mappers add metadata attribute
        }

        return artifact

    def to_engine_vulnerability_match(self, item, now: datetime.datetime):
        artifact = item.get("artifact")
        vuln = item.get("vulnerability")

        vuln_id = vuln.get("id")
        fix_ver = vuln.get("fixedInVersion")
        fix_observed_at = now if fix_ver else None

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
            ),
            artifact=Artifact(
                name=pkg_name,
                version=pkg_version,
                pkg_type=self.engine_type,
                pkg_path=pkg_path,
                cpe="None",  # TODO replace with grype data when available
                cpe23="None",  # TODO replace with grype data when available
            ),
            fix=FixedArtifact(
                versions=[fix_ver] if fix_ver else [],
                wont_fix=False,  # TODO replace with grype data when available
                observed_at=fix_observed_at,
                advisories=[],  # TODO replace with grype data when available
            ),
            match=Match(detected_at=now),
        )

        return vuln_match

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        return None


class RpmMapper(PackageMapper):
    def __init__(self):
        super(RpmMapper, self).__init__(engine_type="rpm", grype_type="rpm")

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        """
        Adds the source package information to grype sbom

        Source package has already been through 2 transformations before this point
        1. From syft sbom to analyzer manifest in anchore_engine/analyzers/syft/handlers/rpm.py
        2. From analyzer manifest to policy-engine ImagePackage in anchore_engine/services/policy_engine/engine/loaders.py

        After the above transformations ImagePackage.src_pkg is the equivalent of syft/grype sourceRpm

        """
        artifact = super().to_grype_artifact(image_package, location_cpes_dict)
        if image_package.normalized_src_pkg != "N/A":
            artifact["metadataType"] = "RpmdbMetadata"
            artifact["metadata"] = {"sourceRpm": image_package.src_pkg}
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
        if distro.lower() in ["redhat", "centos"]:
            distro = "rhel"
        elif distro.lower() == "oraclelinux":
            distro = "ol"
        elif distro.lower() == "amazonlinux":
            distro = "amzn"
        else:
            raise ValueError(
                "Expected distro to be in {} but found {}".format(
                    [
                        "redhat",
                        "centos",
                        "oraclelinux",
                        "amazonlinux",
                    ],
                    distro,
                )
            )

        version = distro_dict.get("version").split(".", 1)[0]

        return "{}:{}".format(distro, version)


class DpkgMapper(PackageMapper):
    def __init__(self):
        super(DpkgMapper, self).__init__(engine_type="dpkg", grype_type="deb")

    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        """
        Adds the source package information to grype sbom

        Source package has already been through 2 transformations before this point. These transformations make the final result more error prone unlike rpm
        1. From syft sbom to analyzer manifest in anchore_engine/analyzers/syft/handlers/debian.py. combines source package and source/package version into one value
        2. From analyzer manifest to policy-engine ImagePackage in anchore_engine/services/policy_engine/engine/loaders.py. attempts to split the source package and version

        After the above transformations ImagePackage.normalized_src_pkg is the closest approximation to syft/grype source.
        Closest because the corner cases are not handled correctly by the above transformations

        Example of not-working case
        Syft output of bsdutils package
        {
           "name": "bsdutils",
           "version": "1:2.20.1-5.3",
           "type": "deb",
           "foundBy": "dpkgdb-cataloger",
           "metadataType": "DpkgMetadata",
           "metadata": {
            "package": "bsdutils",
            "source": "util-linux",
            "version": "1:2.20.1-5.3",
            "sourceVersion": "2.20.1-5.3",
            ...

        Notice version and sourceVersion are different because of the epoch
        - Step 1 processes this into sourcepkg=util-linux-2.20.1-5.3
        - Step 2 falters in it's processing because of the epoch difference and saves util-linux-2.20.1-5.3 to both
        ImagePackage.src_pkg and ImagePackage.normalized_src_pkg. The correct value for normalized_src_pkg is util-linux

        """
        artifact = super().to_grype_artifact(image_package, location_cpes_dict)
        if image_package.normalized_src_pkg != "N/A":
            artifact["metadataType"] = "DpkgMetadata"
            artifact["metadata"] = {"source": image_package.normalized_src_pkg}
        return artifact

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        """
        TODO This tries to map the feed group from grype match. Replace it with feed group from grype
        {
         "type": "ubuntu",
         "version": "8.3"
        }
        """
        distro = distro_dict.get("type")
        if distro.lower() == "ubuntu":
            distro = "ubuntu"
        elif distro.lower() == "debian":
            distro = "debian"
        else:
            raise ValueError(
                "Expected distro to be ubuntu or debian but found {}".format(distro)
            )

        version = distro_dict.get("version")

        return "{}:{}".format(distro, version)


class ApkgMapper(PackageMapper):
    def __init__(self):
        super(ApkgMapper, self).__init__(engine_type="APKG", grype_type="apk")

    def get_feed_group_from_grype_match_distro(self, distro_dict):
        """
        TODO This tries to map the feed group from grype match. Replace it with feed group from grype
        {
         "type": "alpine",
         "version": "8.3"
        }
        """
        distro = distro_dict.get("type")
        if distro.lower() == "alpine":
            distro = "alpine"
        else:
            raise ValueError("Expected distro to be alpine but found {}".format(distro))

        version = distro_dict.get("version").split(".", 1)[0]

        return "{}:{}".format(distro, version)


class CPEMapper(PackageMapper):
    def to_grype_artifact(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[ImageCpe]] = None,
    ):
        artifact = super().to_grype_artifact(image_package)
        artifact["cpes"] = [
            item.get_cpe23_fs_for_sbom()
            for item in location_cpes_dict.get(image_package.pkg_path)
        ]

        return artifact


# key is the engine package type
ENGINE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper(),
    "dpkg": DpkgMapper(),
    "APKG": ApkgMapper(),
    "python": CPEMapper(engine_type="python", grype_type="python"),
    "npm": CPEMapper(engine_type="npm", grype_type="npm"),
    "gem": CPEMapper(engine_type="gem", grype_type="gem"),
    "java": CPEMapper(engine_type="java", grype_type="java-archive"),
}

# key is the grype package type
GRYPE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper(),
    "deb": DpkgMapper(),
    "apk": ApkgMapper(),
    "python": CPEMapper(engine_type="python", grype_type="python"),
    "npm": CPEMapper(engine_type="npm", grype_type="npm"),
    "gem": CPEMapper(engine_type="gem", grype_type="gem"),
    "java-archive": CPEMapper(engine_type="java", grype_type="java-archive"),
    "jenkins-plugin": CPEMapper(engine_type="java", grype_type="jenkins-plugin"),
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
        distro_mapper = ENGINE_DISTRO_MAPPERS.get(image.distro_name)
        if not distro_mapper:
            log.error(
                "No distro mapper found for %s. Cannot generate sbom", image.distro_name
            )
            raise ValueError(
                "No distro mapper found for {}. Cannot generate sbom".format(
                    image.distro_name
                )
            )

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

        for image_package in image_packages:
            pkg_mapper = ENGINE_PACKAGE_MAPPERS.get(image_package.pkg_type)
            if not pkg_mapper:
                log.warn(
                    "No package mapper found for engine package type %s",
                    image_package.pkg_type,
                )
                continue
            artifacts.append(
                pkg_mapper.to_grype_artifact(image_package, location_cpes_dict)
            )

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

            pkg_mapper = GRYPE_PACKAGE_MAPPERS.get(artifact.get("type"))
            if not pkg_mapper:
                log.warn(
                    "No package mapper found for grype package type %s",
                    artifact.get("type"),
                )

            results.append(pkg_mapper.to_engine_vulnerability_match(item, now))

        return results
