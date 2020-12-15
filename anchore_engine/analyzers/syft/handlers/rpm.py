import re

from anchore_engine.analyzers.utils import dig


def save_entry(findings, engine_entry, pkg_key=None):
    if not pkg_key:
        pkg_key = engine_entry.get("name", "")

    findings["package_list"]["pkgs.allinfo"]["base"][pkg_key] = engine_entry


def translate_and_save_entry(findings, artifact):
    """
    Handler function to map syft results for an alpine package type into the engine "raw" document format.
    """
    # _all_package_files(findings, artifact)
    _all_packages(findings, artifact)
    _all_package_info(findings, artifact)


def _all_package_info(findings, artifact):
    name = artifact["name"]
    version = artifact["version"]

    version_pattern = re.match(r"(\S*)-(\S*)", version)
    if version_pattern:
        version = version_pattern.group(1) or version
        release = version_pattern.group(2) or "N/A"

    pkg_value = {
        "type": "rpm",
        "version": version,
        "arch": dig(artifact, "metadata", "architecture", force_default="x86_64"),
        "sourcepkg": dig(artifact, "metadata", "sourceRpm", force_default="N/A"),
        "origin": dig(artifact, "metadata", "vendor", force_default="Centos"),
        "release": release,
        "size": str(dig(artifact, "metadata", "size", force_default="N/A")),
        "license": dig(artifact, "metadata", "license", force_default="N/A"),
        "cpes": artifact.get("cpes", []),
    }
    if pkg_value["arch"] == "amd64":
        pkg_value["arch"] = "x86_64"

    save_entry(findings, pkg_value, name)


def _all_packages(findings, artifact):
    name = artifact["name"]
    version = artifact["version"]
    if name and version:
        findings["package_list"]["pkgs.all"]["base"][name] = version


def _all_package_files(findings, artifact):
    for file in dig(artifact, "metadata", "files", force_default=[]):
        pkgfile = file.get("path")
        findings["package_list"]["pkgfiles.all"]["base"][pkgfile] = "RPMFILE"
