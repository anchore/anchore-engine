import re

from anchore_engine.analyzers.utils import dig, content_hints


def handler(findings, artifact):
    """
    Handler function to map syft results for an debian package type into the engine "raw" document format.
    """
    _all_package_files(findings, artifact)
    _all_packages(findings, artifact)
    _all_packages_plus_source(findings, artifact)
    _all_package_info(findings, artifact)


def _all_package_info(findings, artifact):
    name = artifact['name']
    version = artifact['version']
    release = dig(artifact, 'metadata', 'release')

    if release:
        version = artifact['version'] + "-" + release

    maintainer = dig(artifact, 'metadata', 'maintainer')
    if maintainer:
        maintainer += " (maintainer)"

    size = dig(artifact, 'metadata', 'installedSize')
    if size:
        # convert KB to Bytes
        size = size * 1000
    else:
        size = "N/A"

    source = dig(artifact, 'metadata', 'source')
    if source:
        source = source.split(" ")[0] + "-" + version
    else:
        source = "N/A"

    license = dig(artifact, 'licenses')
    if license:
        license = " ".join(license)
    else:
        license = "Unknown"

    pkg_value = {
        'version': version,
        'sourcepkg': source,
        'arch': dig(artifact, 'metadata', 'architecture', default="N/A") or "N/A",
        'origin': maintainer or "N/A",
        'release': "N/A",
        'size': str(size),
        'license': license,
        'type': "dpkg",
    }

    pkg_updates = content_hints(pkg_type="dpkg")
    pkg_update = pkg_updates.get(name)
    if pkg_update:
        pkg_value.update(pkg_update)

    findings['package_list']['pkgs.allinfo']['base'][name] = pkg_value


def _all_packages_plus_source(findings, artifact):
    name = artifact['name']
    version = artifact["version"]

    origin_package = dig(artifact, "metadata", "originPackage")

    findings['package_list']['pkgs_plus_source.all']['base'][name] = version
    if origin_package:
        findings['package_list']['pkgs_plus_source.all']['base'][origin_package] = version

def _all_packages(findings, artifact):
    name = artifact['name']
    version = artifact["version"]
    if name and version:
        findings['package_list']['pkgs.all']['base'][name] = version

def _all_package_files(findings, artifact):
    for file in dig(artifact, 'metadata', 'files', default=[]):
        original_path = file.get('path')
        if not original_path.startswith("/"):
            # the 'alpine-baselayout' package is installed relative to root, however, syft reports this as an absolute path
            original_path = "/" + original_path
        
        # anchore-engine considers all parent paths to also be a registered apkg path (except root)
        findings['package_list']['pkgfiles.all']['base'][original_path] = "DPKGFILE"
