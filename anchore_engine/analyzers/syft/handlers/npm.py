from anchore_engine.analyzers.utils import dig

def handler(findings, artifact):
    """
    Handler function to map syft results for npm package type into the engine "raw" document format.
    """
    pkg_key = artifact['locations'][0]['path']
    homepage = artifact['metadata'].get('homepage', '')
    author = artifact['metadata'].get('author')
    authors = artifact['metadata'].get('authors', [])
    origins = [] if not author else [author]
    origins.extend(authors)

    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['metadata'].get('url', homepage),
            'origins': origins,
            'lics': artifact['metadata'].get('licenses', []),
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.npms']['base'][pkg_key] = pkg_value

