from anchore_engine.analyzers.utils import dig, content_hints


def handler(findings, artifact):
    """
    Handler function to map syft results for the gem package type into the
    engine "raw" document format.
    """
    pkg_key = artifact['locations'][0]['path']
    name = artifact['name']
    versions = [artifact['version']]

    # craft the artifact document
    pkg_value = {
            'name': name,
            'versions': versions,
            'latest': dig(artifact, 'version', default=""),
            'sourcepkg': dig(artifact, 'metadata', 'homepage', default=""),
            'files': dig(artifact, 'metadata', 'files', default=[]),
            'origins': dig(artifact, 'metadata', 'authors', default=[]),
            'lics': dig(artifact, 'metadata', 'licenses', default=[]),
        }

    pkg_updates = content_hints(pkg_type="gem")
    pkg_update = pkg_updates.get(name)
    if pkg_update:
        pkg_value.update(pkg_update)

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.gems']['base'][pkg_key] = pkg_value
