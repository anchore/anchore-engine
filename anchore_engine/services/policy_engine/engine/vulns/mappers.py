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


class EngineGrypeMapper:
    __engine_distro__ = None
    __grype_os__ = None
    __grype_like_os__ = None
    __engine_distro_pkg_type__ = None
    __grype_os_pkg_type__ = None

    __engine_grype_pkg_type_map__ = {
        "dpkg": "deb",
        "rpm": "rpm",
        "APKG": "apk",
        "java": "java-archive",
        "gem": "gem",
        "npm": "npm",
        "python": "python",
    }

    __grype_engine_pkg_type_map__ = {
        "deb": "dpkg",
        "rpm": "rpm",
        "apk": "APKG",
        "gem": "gem",
        "npm": "npm",
        "python": "python",
        "java-archive": "java",
        "jenkins-plugin": "java",
    }

    def _get_grype_os_pkg_metadata(self, pkg: ImagePackage):
        raise NotImplementedError()

    def transform_image_to_sbom(
        self,
        image: Image,
        image_packages: List[ImagePackage],
        image_cpes: List[ImageCpe],
    ):
        """
        Generate grype sbom from ImagePackage artifacts
        """
        # initialize sbom
        sbom = dict()
        sbom["distro"] = {
            "name": self.__grype_os__,
            "version": image.distro_version,
            "idLike": self.__grype_like_os__,
        }
        sbom["source"] = {
            "type": "image",
            "target": {
                "scope": "Squashed",
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            },
        }

        # map the package (location) to its list of cpes
        location_cpes_dict = defaultdict(list)
        for image_cpe in image_cpes:
            location_cpes_dict[image_cpe.pkg_path].append(image_cpe)

        artifacts = []
        sbom["artifacts"] = artifacts

        for pkg in image_packages:
            grype_pkg_type = self.__engine_grype_pkg_type_map__.get(pkg.pkg_type)
            if not grype_pkg_type:
                log.warn(
                    "Skipping {} since {} package type is not supported by grype".format(
                        pkg.name, pkg.pkg_type
                    )
                )
                continue

            if pkg.pkg_type == self.__engine_distro_pkg_type__:
                art = {
                    "id": str(uuid.uuid4()),
                    "name": pkg.name,
                    "version": pkg.fullversion,
                    "type": grype_pkg_type,
                    "language": "",
                    "locations": [
                        {
                            "path": pkg.pkg_path,
                        }
                    ],
                    # TODO check with alex on how to format source package and version. Override this method in individual mappers
                    "metadata": self._get_grype_os_pkg_metadata(pkg),
                }

            else:
                grype_cpes = [
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
                    for item in location_cpes_dict.get(pkg.pkg_path)
                ]

                art = {
                    "id": str(uuid.uuid4()),
                    "name": pkg.name,
                    "version": pkg.fullversion,
                    "type": grype_pkg_type,
                    "language": pkg.pkg_type,
                    "locations": [
                        {
                            "path": pkg.pkg_path,
                        }
                    ],
                    "cpes": grype_cpes,
                }

            artifacts.append(art)

        # log.debug("image sbom: {}".format(json.dumps(sbom, indent=2)))

        return sbom

    def transform_matches_to_vulnerabilities(self, grype_response):
        """
        Transform grype results into engine vulnerabilities
        """
        # TODO super duper hacky to fit into existing model

        now = datetime.datetime.utcnow()
        matches = grype_response.get("matches", [])

        unique_results = dict()
        dup_count = 0

        for item in matches:
            vuln = item.get("vulnerability")
            artifact = item.get("artifact")

            vuln_id = vuln.get("id")
            fix_ver = vuln.get("fixedInVersion")
            if fix_ver:
                fix_observed_at = now
            else:
                fix_ver = "None"  # barf
                fix_observed_at = None

            engine_nvd_scores = []
            engine_vendor_scores = []  # TODO replace with grype data when available

            grype_cvss_v2 = vuln.get("cvssV2")
            grype_cvss_v3 = vuln.get("cvssV3")

            if grype_cvss_v2 or grype_cvss_v3:
                engine_score = CvssCombined(id=vuln_id)
                engine_nvd_scores.append(engine_score)

                if grype_cvss_v2:
                    engine_score.cvss_v2 = CvssScore(
                        base_score=grype_cvss_v2.get("baseScore"),
                        exploitability_score=grype_cvss_v2.get("exploitabilityScore"),
                        impact_score=grype_cvss_v2.get("impactScore"),
                    )

                if grype_cvss_v3:
                    engine_score.cvss_v3 = CvssScore(
                        base_score=grype_cvss_v3.get("baseScore"),
                        exploitability_score=grype_cvss_v3.get("exploitabilityScore"),
                        impact_score=grype_cvss_v3.get("impactScore"),
                    )

            pkg_type = self.__grype_engine_pkg_type_map__.get(artifact.get("type"))
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
                is_legacy = True
                feed = "vulnerabilities"
                distro = search_key.get("distro")

                distro_type = distro.get("type")
                if distro_type.lower() == "redhat":
                    feed_group = "rhel:"
                else:
                    feed_group = distro_type.lower() + ":"

                distro_version = distro.get("version")
                group = distro_version.split(".", 1)[0]
                feed_group += group
            elif vuln_id.startswith("GHSA"):
                is_legacy = True
                feed = "vulnerabilities"
                feed_group = "github:{}".format(pkg_type)
            elif vuln_id.startswith("VULNDB"):  # this is absolutely WRONG!!!
                feed = "vulndb"
                feed_group = "vulndb:vulnerabilities"
            else:
                feed = "nvdv2"
                feed_group = "nvdv2:cves"

            vuln_tuple = (vuln_id, feed_group, pkg_name, pkg_version, pkg_path)
            if vuln_tuple in unique_results:
                log.warn(
                    "{} in {} namespace detected for {} {}, skipping".format(
                        vuln_id, vuln_id, pkg_name, pkg_version
                    )
                )
                dup_count += 1
                continue
            else:
                unique_results[vuln_tuple] = VulnerabilityMatch(
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
                        pkg_type=pkg_type,
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

        log.info(
            "Number of unique vulnerabilities: {}, duplicates: {}".format(
                len(unique_results), dup_count
            )
        )

        return list(unique_results.values())


class RHELMapper(EngineGrypeMapper):
    __engine_distro__ = "rhel"
    __engine_distro_pkg_type__ = "rpm"
    __grype_os__ = "redhat"
    __grype_os_pkg_type__ = "rpm"
    __grype_like_os__ = "fedora"

    def _get_grype_os_pkg_metadata(self, pkg: ImagePackage):
        return {"sourceRpm": pkg.src_pkg} if pkg.src_pkg != "N/A" else dict()


class CentOSMapper(RHELMapper):
    __engine_distro__ = "centos"
    __grype_os__ = "centos"


class DebianMapper(EngineGrypeMapper):
    __engine_distro__ = "debian"
    __engine_distro_pkg_type__ = "dpkg"
    __grype_os__ = "debian"
    __grype_os_pkg_type__ = "deb"
    __grype_like_os__ = "debian"

    def _get_grype_os_pkg_metadata(self, pkg: ImagePackage):
        return dict()


class UbuntuMapper(DebianMapper):
    __engine_distro__ = "ubuntu"
    __grype_os__ = "ubuntu"


class AlpineMapper(EngineGrypeMapper):
    __engine_distro__ = "alpine"
    __engine_distro_pkg_type__ = "APKG"
    __grype_os__ = "alpine"
    __grype_os_pkg_type__ = "apkg"
    __grype_like_os__ = "alpine"

    def _get_grype_os_pkg_metadata(self, pkg: ImagePackage):
        return None


DISTRO_MAPPERS = {
    RHELMapper.__engine_distro__: RHELMapper,
    CentOSMapper.__engine_distro__: CentOSMapper,
    DebianMapper.__engine_distro__: DebianMapper,
    UbuntuMapper.__engine_distro__: UbuntuMapper,
    AlpineMapper.__engine_distro__: AlpineMapper,
}
