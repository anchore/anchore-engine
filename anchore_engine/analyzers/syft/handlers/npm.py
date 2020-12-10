from anchore_engine.analyzers.utils import dig


def save_entry(findings, engine_entry, pkg_key=None):
    if not pkg_key:
        pkg_location = engine_entry.get("location", "")
        if pkg_location:
            # derive the key from the entries 'location' value
            pkg_key = pkg_location
        else:
            # derive the key from a 'virtual' location
            pkg_name = engine_entry.get("name", "")
            pkg_version = engine_entry.get(
                "version", engine_entry.get("latest", "")
            )  # rethink this... ensure it's right
            pkg_key = "/virtual/npmpkg/{}-{}".format(pkg_name, pkg_version)

    findings["package_list"]["pkgs.npms"]["base"][pkg_key] = engine_entry


def translate_and_save_entry(findings, artifact):
    """
    Handler function to map syft results for npm package type into the engine "raw" document format.
    """
    pkg_key = artifact["locations"][0]["path"]
    name = artifact["name"]
    homepage = dig(artifact, "metadata", "homepage", force_default="")
    author = dig(artifact, "metadata", "author", force_default="")
    authors = dig(artifact, "metadata", "authors", force_default=[])
    origins = [] if not author else [author]
    origins.extend(authors)

    pkg_value = {
        "name": name,
        "versions": [artifact["version"]],
        "latest": artifact["version"],
        "sourcepkg": dig(artifact, "metadata", "url", force_default=homepage),
        "origins": origins,
        "lics": dig(artifact, "metadata", "licenses", force_default=[]),
        "cpes": artifact.get("cpes", []),
    }

    # inject the artifact document into the "raw" analyzer document
    save_entry(findings, pkg_value, pkg_key)
