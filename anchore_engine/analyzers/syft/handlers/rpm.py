import re

from anchore_engine.analyzers.utils import dig, content_hints


def handler(findings, artifact):
    """
    Handler function to map syft results for an alpine package type into the engine "raw" document format.
    """
    # _all_package_files(findings, artifact)
    _all_packages(findings, artifact)
    _all_package_info(findings, artifact)


def _all_package_info(findings, artifact):
    name = artifact['name']
    version = artifact['version']

    version_pattern = re.match(r"(\S*)-(\S*)", version)
    if version_pattern:
        version = version_pattern.group(1) or version
        release = version_pattern.group(2) or "N/A"

    pkg_value = {
        'type': "rpm",
        'version': version,
        'arch': dig(artifact, 'metadata', 'architecture', default="x86_64"),
        'sourcepkg': dig(artifact, 'metadata', 'sourceRpm', default="N/A"),
        'origin': dig(artifact, 'metadata', 'vendor', default="Centos"),
        'release': release,
        'size': str(dig(artifact, 'metadata', 'size', default="N/A")),
        'license': dig(artifact, 'metadata', 'license', default="N/A"),
    }
    if pkg_value['arch'] == 'amd64':
        pkg_value['arch'] = 'x86_64'

    pkg_updates = content_hints(pkg_type="rpm")
    pkg_update = pkg_updates.get(name)

    if pkg_update:
        pkg_value.update(pkg_update)

    findings['package_list']['pkgs.allinfo']['base'][name] = pkg_value


def _all_packages(findings, artifact):
    name = artifact['name']
    version = artifact["version"]
    if name and version:
        findings['package_list']['pkgs.all']['base'][name] = version


def _all_package_files(findings, artifact):
    for file in dig(artifact, 'metadata', 'files', default=[]):
        pkgfile = file.get('path')
        findings['package_list']['pkgfiles.all']['base'][pkgfile] = "RPMFILE"
