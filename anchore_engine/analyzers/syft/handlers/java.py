from anchore_engine.analyzers.utils import dig, content_hints


def handler(findings, artifact):
    """
    Handler function to map syft results for java-archive and jenkins-plugin types into the engine "raw" document format.
    """
    pkg_key = dig(artifact, 'metadata', 'virtualPath', default="N/A")

    virtualElements = pkg_key.split(":")
    if "." in virtualElements[-1]:
        # there may be an extension in the virtual path, use it
        java_ext = virtualElements[-1].split(".")[-1]
    else:
        # the last field is probably a package name, use the second to last virtual path element and extract the
        # extension
        java_ext = virtualElements[-2].split(".")[-1]

    # per the manifest specification https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest
    # these fields SHOULD be in the main section, however, there are multiple java packages found
    # where this information is thrown into named subsections.

    # Today anchore-engine reads key-value pairs in all sections into one large map --this behavior is replicated here.

    values = {}

    main_section = dig(artifact, 'metadata', 'manifest', 'main', default={})
    named_sections = dig(artifact, 'metadata', 'manifest', 'namedSections', default={})
    for name, section in [('main', main_section)] + [pair for pair in named_sections.items()]:
        for field, value in section.items():
            values[field] = value

    # find the origin
    group_id = dig(artifact, 'metadata', 'pomProperties', 'groupId')
    origin = values.get('Specification-Vendor')
    if not origin:
        origin = values.get('Implementation-Vendor')

    # use pom properties over manifest info (if available)
    if group_id:
        origin = group_id

    pkg_value = {
        'name': artifact['name'],
        'specification-version': values.get('Specification-Version', "N/A"),
        'implementation-version': values.get('Implementation-Version', "N/A"),
        'maven-version': dig(artifact, 'metadata', 'pomProperties', 'version', default="N/A"),
        'origin': origin or "N/A",
        'location': pkg_key, # this should be related to full path
        'type': "java-" + java_ext,
    }

    pkg_updates = content_hints(pkg_type="java")
    pkg_update = pkg_updates.get(name)
    if pkg_update:
        pkg_value.update(pkg_update)

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.java']['base'][pkg_key] = pkg_value

