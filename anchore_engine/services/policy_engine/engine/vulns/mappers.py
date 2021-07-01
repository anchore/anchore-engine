import copy
import datetime
import uuid
from collections import defaultdict
from typing import Dict, List

from anchore_engine.common.models.policy_engine import (
    CVSS,
    Advisory,
    Artifact,
    FixedArtifact,
    Match,
    NVDReference,
    Vulnerability,
    VulnerabilityMatch,
)
from anchore_engine.db import Image, ImageCpe, ImagePackage
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


class PackageMapper:
    def __init__(self, engine_type, grype_type, grype_language=None):
        self.engine_type = engine_type
        self.grype_type = grype_type
        # default language to blank string
        self.grype_language = grype_language if grype_language else ""

    def to_grype(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = {
            "id": str(uuid.uuid4()),
            "name": image_package.name,
            "version": image_package.fullversion,
            "type": self.grype_type,
            "locations": [
                {
                    "path": image_package.pkg_path,
                }
            ],
            # Package type specific mappers add metadata attribute
        }

        return artifact


class RpmMapper(PackageMapper):
    def __init__(self):
        super(RpmMapper, self).__init__(engine_type="rpm", grype_type="rpm")

    def to_grype(
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
        artifact = super().to_grype(image_package, location_cpes_dict)
        if image_package.normalized_src_pkg != "N/A":
            artifact["metadataType"] = "RpmdbMetadata"
            artifact["metadata"] = {"sourceRpm": image_package.src_pkg}
        return artifact


class DpkgMapper(PackageMapper):
    def __init__(self):
        super(DpkgMapper, self).__init__(engine_type="dpkg", grype_type="deb")

    def to_grype(
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
        artifact = super().to_grype(image_package, location_cpes_dict)
        if image_package.normalized_src_pkg != "N/A":
            artifact["metadataType"] = "DpkgMetadata"
            artifact["metadata"] = {"source": image_package.normalized_src_pkg}
        return artifact


class ApkgMapper(PackageMapper):
    def __init__(self):
        super(ApkgMapper, self).__init__(engine_type="APKG", grype_type="apk")

    def to_grype(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[str]] = None,
    ):
        artifact = super().to_grype(image_package, location_cpes_dict)

        # pkgdb/ prefix is added to all os package locations, it's the only way to associate a package with it's cpes
        cpes = location_cpes_dict.get(f"pkgdb/{image_package.name}")
        if cpes:
            # populate cpes for os packages
            artifact["cpes"] = [cpe.get_cpe23_fs_for_sbom() for cpe in cpes]

        return artifact


class CPEMapper(PackageMapper):
    def to_grype(
        self,
        image_package: ImagePackage,
        location_cpes_dict: Dict[str, List[ImageCpe]] = None,
    ):
        cpes = location_cpes_dict.get(image_package.pkg_path)
        if cpes:
            artifact = {
                "id": str(uuid.uuid4()),
                "name": image_package.name,
                "type": self.grype_type,
                "language": self.grype_language,
                "locations": [
                    {
                        "path": image_package.pkg_path,
                    }
                ],
                "cpes": [cpe.get_cpe23_fs_for_sbom() for cpe in cpes],
                "version": cpes[0].version,  # set the version explicitly for grype
            }

            return artifact
        else:
            raise ValueError("No CPEs found for package={}".format(image_package.name))


class VulnerabilityMapper:
    @staticmethod
    def _try_parse_cvss(cvss_list: List[Dict]) -> List[CVSS]:
        """
        Best effort attempt at parsing CVSS from response. Ignores any errors raised and chugs along
        """
        cvss_objects = []
        if isinstance(cvss_list, list) and cvss_list:
            for cvss_dict in cvss_list:
                try:
                    cvss_objects.append(
                        CVSS(
                            version=cvss_dict.get("version"),
                            vector=cvss_dict.get("vector"),
                            base_score=cvss_dict.get("metrics", {}).get(
                                "baseScore", -1.0
                            ),
                            exploitability_score=cvss_dict.get("metrics", {}).get(
                                "exploitabilityScore", -1.0
                            ),
                            impact_score=cvss_dict.get("metrics", {}).get(
                                "impactScore", -1.0
                            ),
                        )
                    )
                except (AttributeError, ValueError):
                    log.debug("Ignoring error parsing CVSS dict %s", cvss_dict)

        return cvss_objects

    @staticmethod
    def _try_parse_related_vulnerabilities(
        vulns: List[Dict],
    ) -> List[NVDReference]:
        """
        Best effort attempt at parsing other vulnerabilities from grype response. Ignores any errors raised and chugs along
        """
        nvd_objects = []
        if isinstance(vulns, list) and vulns:
            for vuln_dict in vulns:
                try:
                    nvd_objects.append(
                        NVDReference(
                            vulnerability_id=vuln_dict.get("id"),
                            # description=vuln_dict.get("description"),
                            description=None,
                            severity=vuln_dict.get("severity"),
                            link=vuln_dict.get("dataSource"),
                            cvss=VulnerabilityMapper._try_parse_cvss(
                                vuln_dict.get("cvss", [])
                            ),
                        )
                    )
                except (AttributeError, ValueError):
                    log.debug(
                        "Ignoring error parsing related vulnerability dict %s",
                        vuln_dict,
                    )

        return nvd_objects

    @staticmethod
    def _try_parse_advisories(
        advisories: List[Dict],
    ) -> List[Advisory]:
        """
        Best effort attempt at parsing advisories from grype response. Ignores any errors raised and chugs along
        """
        advisory_objects = []
        if isinstance(advisories, list) and advisories:
            for advisory_dict in advisories:
                try:
                    # TODO format check with toolbox
                    advisory_objects.append(
                        Advisory(
                            id=advisory_dict.get("id"), link=advisory_dict.get("link")
                        )
                    )
                except (AttributeError, ValueError):
                    log.debug(
                        "Ignoring error parsing advisory dict %s",
                        advisory_dict,
                    )

        return advisory_objects

    @staticmethod
    def _try_parse_matched_cpes(match_dict: Dict) -> List[str]:
        """
        Best effort attempt at parsing cpes that were matched from matchDetails of grype response.

        Input is a dictionary representing a single grype match output, the attribute of interest here is matchDetails
        {
          "matchDetails": [
            {
              "matcher": "java-matcher",
              "searchedBy": {
                "namespace": "nvd",
                "cpes": [
                  "cpe:2.3:a:*:spring_framework:5.2.6.RELEASE:*:*:*:*:*:*:*"
                ]
              },
              "matchedOn": {
                "versionConstraint": "<= 4.2.9 || >= 4.3.0, <= 4.3.28 || >= 5.0.0, <= 5.0.18 || >= 5.1.0, <= 5.1.17 || >= 5.2.0, <= 5.2.8 (unknown)",
                "cpes": [
                  "cpe:2.3:a:pivotal_software:spring_framework:*:*:*:*:*:*:*:*"
                ]
              }
            }
          ]
          ...
        }
        """
        cpes = []
        if match_dict and isinstance(match_dict, dict):
            try:
                matchers = match_dict.get("matchDetails", [])
                for matcher in matchers:
                    matcher_cpes = matcher.get("searchedBy", {}).get("cpes", [])
                    if matcher_cpes:
                        cpes.extend(matcher_cpes)
            except (AttributeError, ValueError):
                log.warn("Ignoring error parsing cpes")

        return list(set(cpes))

    def to_engine(
        self,
        result: Dict,
        package_mapper: PackageMapper,
        now: datetime.datetime,
    ):
        artifact_dict = result.get("artifact")
        vuln_dict = result.get("vulnerability")

        # parse cvss fields
        cvss_objs = VulnerabilityMapper._try_parse_cvss(vuln_dict.get("cvss", []))

        # parse fix details
        fix_dict = vuln_dict.get("fix")
        fix_obj = FixedArtifact(
            versions=[], wont_fix=False, observed_at=None, advisories=[]
        )
        if fix_dict:
            fix_obj.versions = fix_dict.get("versions", [])
            fix_obj.wont_fix = (
                fix_dict.get("state").lower() == "wont-fix"
            )  # TODO format check with toolbox
            fix_obj.observed_at = now if fix_obj.versions else None
            fix_obj.advisories = VulnerabilityMapper._try_parse_advisories(
                fix_dict.get("advisories", [])
            )

        # parse nvd references
        nvd_objs = VulnerabilityMapper._try_parse_related_vulnerabilities(
            result.get("relatedVulnerabilities", [])
        )

        # parse package path
        pkg_path = (
            artifact_dict.get("locations")[0].get("path")
            if artifact_dict.get("locations")
            else "NA"
        )

        vuln_match = VulnerabilityMatch(
            vulnerability=Vulnerability(
                vulnerability_id=vuln_dict.get("id"),
                description=vuln_dict.get("description"),
                severity=vuln_dict.get("severity"),
                link=vuln_dict.get("dataSource"),
                feed="grypedb",
                feed_group=vuln_dict.get("namespace"),
                cvss=cvss_objs,
            ),
            artifact=Artifact(
                name=artifact_dict.get("name"),
                version=artifact_dict.get("version"),
                pkg_type=package_mapper.engine_type,
                location=pkg_path,
                cpe=None,  # vestige of the old system
                cpes=self._try_parse_matched_cpes(result),
            ),
            fix=fix_obj,
            match=Match(detected_at=now),
            nvd=nvd_objs,
        )

        return vuln_match


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
    "ol": DistroMapper(
        engine_distro="ol", grype_os="oraclelinux", grype_like_os="fedora"
    ),
    "amzn": DistroMapper(
        engine_distro="amzn", grype_os="amazonlinux", grype_like_os="fedora"
    ),
    "centos": DistroMapper(
        engine_distro="centos", grype_os="centos", grype_like_os="fedora"
    ),
    "busybox": DistroMapper(
        engine_distro="busybox", grype_os="busybox", grype_like_os=""
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
    "oraclelinux": DistroMapper(
        engine_distro="ol", grype_os="oraclelinux", grype_like_os="fedora"
    ),
    "amazonlinux": DistroMapper(
        engine_distro="amzn", grype_os="amazonlinux", grype_like_os="fedora"
    ),
    "centos": DistroMapper(
        engine_distro="centos", grype_os="centos", grype_like_os="fedora"
    ),
    "busybox": DistroMapper(
        engine_distro="busybox", grype_os="busybox", grype_like_os=""
    ),
}

# key is the engine package type
ENGINE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper(),
    "dpkg": DpkgMapper(),
    "APKG": ApkgMapper(),
    "apkg": ApkgMapper(),
    "python": CPEMapper(
        engine_type="python", grype_type="python", grype_language="python"
    ),
    "npm": CPEMapper(engine_type="npm", grype_type="npm", grype_language="javascript"),
    "gem": CPEMapper(engine_type="gem", grype_type="gem", grype_language="ruby"),
    "java": CPEMapper(
        engine_type="java", grype_type="java-archive", grype_language="java"
    ),
    "go": CPEMapper(engine_type="go", grype_type="go", grype_language="go"),
    "binary": CPEMapper(engine_type="binary", grype_type="binary"),
    "maven": CPEMapper(
        engine_type="maven", grype_type="java-archive", grype_language="java"
    ),
    "js": CPEMapper(engine_type="js", grype_type="js", grype_language="javascript"),
    "composer": CPEMapper(engine_type="composer", grype_type="composer"),
    "nuget": CPEMapper(engine_type="nuget", grype_type="nuget"),
}

# key is the grype package type
GRYPE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper(),
    "deb": DpkgMapper(),
    "apk": ApkgMapper(),
    "python": CPEMapper(
        engine_type="python", grype_type="python", grype_language="python"
    ),
    "npm": CPEMapper(engine_type="npm", grype_type="npm", grype_language="javascript"),
    "gem": CPEMapper(engine_type="gem", grype_type="gem", grype_language="ruby"),
    "java-archive": CPEMapper(
        engine_type="java", grype_type="java-archive", grype_language="java"
    ),
    "jenkins-plugin": CPEMapper(
        engine_type="java", grype_type="jenkins-plugin", grype_language="java"
    ),
    "go": CPEMapper(engine_type="go", grype_type="go", grype_language="go"),
    "binary": CPEMapper(engine_type="binary", grype_type="binary"),
    "js": CPEMapper(engine_type="js", grype_type="js", grype_language="javascript"),
    "composer": CPEMapper(engine_type="composer", grype_type="composer"),
    "nuget": CPEMapper(engine_type="nuget", grype_type="nuget"),
}

GRYPE_MATCH_MAPPER = VulnerabilityMapper()


def to_grype_sbom(
    image: Image,
    image_packages: List[ImagePackage],
    image_cpes: List[ImageCpe],
):
    """
    Generate grype sbom using Image artifacts
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
                "No mapper found for engine package type %s, defaulting to CPE mapper",
                image_package.pkg_type,
            )
            pkg_mapper = CPEMapper(
                engine_type=image_package.pkg_path, grype_type=image_package.pkg_path
            )

        try:
            artifacts.append(pkg_mapper.to_grype(image_package, location_cpes_dict))
        except Exception:
            log.exception(
                "Ignoring error in engine->grype transformation for %s package %s, skipping it from sbom",
                image_package.pkg_type,
                image_package.name,
            )

    return sbom


def to_engine_vulnerabilities(grype_response):
    """
    Transform grype results into engine vulnerabilities
    """

    now = datetime.datetime.utcnow()
    matches = grype_response.get("matches", []) if grype_response else []
    results = []

    for item in matches:
        artifact = item.get("artifact")

        pkg_mapper = GRYPE_PACKAGE_MAPPERS.get(artifact.get("type"))
        if not pkg_mapper:
            log.warn(
                "No mapper found for grype artifact type %s, skipping vulnerability match",
                artifact.get("type"),
            )
            continue

        try:
            results.append(GRYPE_MATCH_MAPPER.to_engine(item, pkg_mapper, now))
        except Exception:
            log.exception(
                "Ignoring error in grype->engine transformation for vulnerability match, skipping it from report",
            )

    return results


class EngineGrypeDBMapper:
    def _transform_cvss(self, cvss, cvss_template):
        score_dict = copy.deepcopy(cvss_template)
        score_dict["version"] = cvss.get("Version")
        score_dict["vector"] = cvss.get("Vector", None)
        score_dict["base_score"] = cvss.get("Metrics", {}).get("BaseScore", -1.0)
        score_dict["expolitability_score"] = cvss.get("Metrics", {}).get(
            "ExploitabilityScore", -1.0
        )
        score_dict["impact_score"] = cvss.get("Metrics", {}).get("ImpactScore", -1.0)
        return score_dict

    def to_engine_vulnerabilities(self, grype_vulnerabilities):
        """
        Receives a list of vulnerability_metadata records from grype_db and returns a list of vulnerabilities mapped
        into the data structure engine expects.
        """
        transformed_vulnerabilities = []
        intermediate_tuple_list = {}

        return_el_template = {
            "id": None,  # done
            "namespace": None,  # done
            "severity": None,  # done
            "link": None,  # done
            "affected_packages": [],  # done
            "description": None,  # done
            "references": None,  # leaving this be
            "nvd_data": [],
            "vendor_data": [],  # leaving this be
        }
        cvss_template = {
            "version": None,
            "vector": None,
            "base_score": -1.0,
            "expolitability_score": -1.0,
            "impact_score": -1.0,
        }

        for grype_raw_result in grype_vulnerabilities:
            grype_vulnerability = grype_raw_result.GrypeVulnerability
            grype_vulnerability_metadata = grype_raw_result.GrypeVulnerabilityMetadata

            vuln_dict = intermediate_tuple_list.get(
                (
                    grype_vulnerability_metadata.id,
                    grype_vulnerability_metadata.namespace,
                )
            )

            if not vuln_dict:
                vuln_dict = copy.deepcopy(return_el_template)
                intermediate_tuple_list[
                    (
                        grype_vulnerability_metadata.id,
                        grype_vulnerability_metadata.namespace,
                    )
                ] = vuln_dict

                vuln_dict["id"] = grype_vulnerability_metadata.id
                vuln_dict["namespace"] = grype_vulnerability_metadata.namespace
                vuln_dict["description"] = grype_vulnerability_metadata.description
                vuln_dict["severity"] = grype_vulnerability_metadata.severity
                vuln_dict["link"] = grype_vulnerability_metadata.data_source
                vuln_dict["references"] = grype_vulnerability_metadata.deserialized_urls

                # Transform the cvss blocks
                cvss_combined = grype_vulnerability_metadata.deserialized_cvss

                for cvss in cvss_combined:
                    version = cvss["Version"]
                    if version.startswith("2"):
                        score_dict = self._transform_cvss(cvss, cvss_template)

                        vuln_dict["vendor_data"].append(
                            {
                                "cvss_v2": score_dict,
                                "id": grype_vulnerability_metadata.id,
                            }
                        )
                    elif version.startswith("3"):
                        score_dict = self._transform_cvss(cvss, cvss_template)

                        vuln_dict["vendor_data"].append(
                            {
                                "cvss_v3": score_dict,
                                "id": grype_vulnerability_metadata.id,
                            }
                        )
                    else:
                        log.warn(
                            "Omitting the following cvss with unknown version from vulnerability %s: %s",
                            grype_vulnerability_metadata.id,
                            cvss,
                        )
                        continue

                # parse_nvd_data() using grype_vulnerability_metadata

            # results are produced by left outer join, hence the check
            if grype_vulnerability:

                # Transform the versions block
                if grype_vulnerability.deserialized_fixed_in_versions:
                    version = ",".join(
                        grype_vulnerability.deserialized_fixed_in_versions
                    )
                else:
                    version = "*"

                # Populate affected_packages
                vuln_dict["affected_packages"].append(
                    {
                        "name": grype_vulnerability.package_name,
                        "type": grype_vulnerability.version_format,
                        "version": version,
                    }
                )

        return list(intermediate_tuple_list.values())
