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
    _all_package_files(findings, artifact)
    _all_packages(findings, artifact)
    _all_packages_plus_source(findings, artifact)
    _all_package_info(findings, artifact)


def _all_package_info(findings, artifact):
    name = artifact["name"]
    version = artifact["version"]

    release = "N/A"
    version_pattern = re.match(r"(\S*)-(\S*)", version)
    if version_pattern:
        version = version_pattern.group(1) or version
        release = version_pattern.group(2) or "N/A"

    pkg_value = {
        "name": name,
        "version": version,
        "sourcepkg": dig(artifact, "metadata", "originPackage", force_default="N/A"),
        "arch": dig(artifact, "metadata", "architecture", force_default="N/A"),
        "origin": dig(artifact, "metadata", "maintainer", force_default="N/A"),
        "release": release,
        "size": str(dig(artifact, "metadata", "installedSize", force_default="N/A")),
        "license": dig(artifact, "metadata", "license", force_default="N/A"),
        "type": "APKG",
        "files": [
            f.get("path") for f in dig(artifact, "metadata", "files", force_default=[])
        ],
        "cpes": artifact.get("cpes", []),
    }

    # inject the artifact document into the "raw" analyzer document
    save_entry(findings, pkg_value, name)


def _all_packages_plus_source(findings, artifact):
    name = artifact["name"]
    version = artifact["version"]

    origin_package = dig(artifact, "metadata", "originPackage")

    findings["package_list"]["pkgs_plus_source.all"]["base"][name] = version
    if origin_package:
        findings["package_list"]["pkgs_plus_source.all"]["base"][
            origin_package
        ] = version


def _all_packages(findings, artifact):
    name = artifact["name"]
    version = artifact["version"]
    if name and version:
        findings["package_list"]["pkgs.all"]["base"][name] = version


def _all_package_files(findings, artifact):
    for file in dig(artifact, "metadata", "files", force_default=[]):
        original_path = file.get("path")
        if not original_path.startswith("/"):
            # the 'alpine-baselayout' package is installed relative to root,
            # however, syft reports this as an absolute path
            original_path = "/" + original_path

        # anchore-engine considers all parent paths to also be a registered apkg path (except root)
        findings["package_list"]["pkgfiles.all"]["base"][original_path] = "APKFILE"
