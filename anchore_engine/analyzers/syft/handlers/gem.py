from anchore_engine.analyzers.utils import dig


def handler(findings, artifact):
    """
    Handler function to map syft results for the gem package type into the engine "raw" document format.
    """
    pkg_key = artifact['locations'][0]['path']

    # craft the artifact document
    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['metadata'].get('homepage', ''),
            'files': artifact['metadata'].get('files', []),
            'origins': artifact['metadata'].get('authors', []),
            'lics': artifact['metadata'].get('licenses', []),
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.gems']['base'][pkg_key] = pkg_value
