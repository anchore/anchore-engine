import datetime
import uuid
from collections import defaultdict
from typing import List, Dict

from anchore_engine.db import Image, ImageCpe, ImagePackage
from anchore_engine.common.models.policy_engine import (
    VulnerabilityMatch,
    Artifact,
    Vulnerability,
    Match,
    FixedArtifact,
    Advisory,
    CVSS,
    NVDReference,
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
                feed="vulnerabilities",
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
}

# key is the engine package type
ENGINE_PACKAGE_MAPPERS = {
    "rpm": RpmMapper(),
    "dpkg": DpkgMapper(),
    "APKG": ApkgMapper(),
    "python": CPEMapper(
        engine_type="python", grype_type="python", grype_language="python"
    ),
    "npm": CPEMapper(engine_type="npm", grype_type="npm", grype_language="javascript"),
    "gem": CPEMapper(engine_type="gem", grype_type="gem", grype_language="ruby"),
    "java": CPEMapper(
        engine_type="java", grype_type="java-archive", grype_language="java"
    ),
    "go": CPEMapper(engine_type="go", grype_type="go", grype_language="go"),
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
                "No package mapper found for engine package type %s",
                image_package.pkg_type,
            )
            continue

        try:
            artifacts.append(pkg_mapper.to_grype(image_package, location_cpes_dict))
        except Exception:
            log.exception(
                "Ignoring error in engine->grype transformation for {} package {}, skipping it from sbom",
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
                "No package mapper found for grype package type %s",
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
    def _to_engine_vulnerability(self, grype_vulnerability):
        """
        Receives a single vulnerability_metadata record from grype_db and maps into the data structure engine expects.
        The vulnerability_metadata record may optionally (but in practice should always) have a nested record for the
        related vulnerability record.
        """
        # Create the templated output object
        output_vulnerability = {}
        return_el_template = {
            "id": None,
            "namespace": None,
            "severity": None,
            "link": None,
            "affected_packages": None,
            "description": None,
            "references": None,
            "nvd_data": None,
            "vendor_data": None,
        }
        output_vulnerability.update(return_el_template)

        # Set mapped field values
        output_vulnerability["id"] = grype_vulnerability.id
        output_vulnerability["description"] = grype_vulnerability.description
        output_vulnerability["severity"] = grype_vulnerability.severity

        # TODO What should we do with multiple links. Currently just grabbing the first one
        if grype_vulnerability.deserialized_links:
            output_vulnerability["link"] = grype_vulnerability.deserialized_links[0]
        else:
            output_vulnerability["link"] = []

        # TODO Not sure yet how these should be mapped
        output_vulnerability["references"] = None

        vendor_data = {}
        vendor_data["id"] = grype_vulnerability.id

        # Transform the cvss blocks
        cvss_v2 = []
        cvss_v3 = []
        cvss_combined = grype_vulnerability.deserialized_cvss

        for cvss in cvss_combined:
            if cvss["Version"].startswith["2"]:
                cvss_v2.append(cvss)
            elif cvss["Version"].startswith["3"]:
                cvss_v3.append(cvss)
            else:
                continue  # TODO Delete this line, just log
                # TODO Log an unknown CVSS version
        vendor_data["cvss_v2"] = cvss_v2
        vendor_data["cvss_v3"] = cvss_v3

        if (
            grype_vulnerability.record_source
            and grype_vulnerability.record_source.startswith("nvdv2")
        ):
            output_vulnerability["nvd_data"] = [vendor_data]
            output_vulnerability["vendor_data"] = []
        else:
            output_vulnerability["nvd_data"] = []
            output_vulnerability["vendor_data"] = [vendor_data]

        # Get fields from the nested vulnerability object, if it exists
        if grype_vulnerability.vulnerability is not None:
            output_vulnerability[
                "namespace"
            ] = grype_vulnerability.vulnerability.namespace

            affected_package = {}
            affected_package["name"] = grype_vulnerability.vulnerability.package_name
            affected_package["type"] = grype_vulnerability.vulnerability.version_format
            affected_package[
                "version"
            ] = grype_vulnerability.vulnerability.version_constraint
            output_vulnerability["affected_packages"] = [affected_package]

        return output_vulnerability

    def to_engine_vulnerabilities(self, grype_vulnerabilities):
        """
        Receives a list of vulnerability_metadata records from grype_db and returns a list of vulnerabilities mapped
        into the data structure engine expects.
        """
        transformed_vulnerabilities = []
        for grype_raw_result in grype_vulnerabilities:
            transformed_vulnerabilities.append(
                self._transform_grype_vulnerability(grype_raw_result)
            )

        return transformed_vulnerabilities
