import os

from anchore_engine.analyzers.utils import dig


def handler(findings, artifact):
    """
    Handler function to map syft results for the python package type into the engine "raw" document format.
    """
    if "python-package-cataloger" not in artifact['foundBy']:
        # engine only includes python findings for egg and wheel installations (with rich metadata)
        return

    site_pkg_root = artifact['metadata']['sitePackagesRootPath']

    # anchore engine always uses the name, however, the name may not be a top-level package
    # instead default to the first top-level package unless the name is listed among the
    # top level packages explicitly defined in the metadata
    pkg_key_name = artifact['metadata']['topLevelPackages'][0]
    if artifact['name'] in artifact['metadata']['topLevelPackages']:
        pkg_key_name = artifact['name']

    pkg_key = os.path.join(site_pkg_root, pkg_key_name)
    origin = artifact['metadata'].get('author', "")
    email = artifact['metadata'].get('authorEmail', None)
    if email:
        origin += " <%s>" % email

    files = []
    for file in artifact['metadata'].get('files', []):
        files.append(os.path.join(site_pkg_root, file['path']))

    # craft the artifact document
    pkg_value = {
            'name': artifact['name'],
            'version': artifact['version'],
            'latest': artifact['version'],
            'files': files,
            'origin': origin,
            'license': artifact['metadata'].get('license', ""),
            'location': site_pkg_root,
            'type': 'python',
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.python']['base'][pkg_key] = pkg_value
