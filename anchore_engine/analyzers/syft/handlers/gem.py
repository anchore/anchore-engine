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
            pkg_key = "/virtual/gempkg/{}-{}".format(pkg_name, pkg_version)

    findings["package_list"]["pkgs.gems"]["base"][pkg_key] = engine_entry


def translate_and_save_entry(findings, artifact):
    """
    Handler function to map syft results for the gem package type into the
    engine "raw" document format.
    """
    pkg_key = artifact["locations"][0]["path"]
    name = artifact["name"]
    versions = [artifact["version"]]

    # craft the artifact document
    pkg_value = {
        "name": name,
        "versions": versions,
        "latest": dig(artifact, "version", force_default=""),
        "sourcepkg": dig(artifact, "metadata", "homepage", force_default=""),
        "files": dig(artifact, "metadata", "files", force_default=[]),
        "origins": dig(artifact, "metadata", "authors", force_default=[]),
        "lics": dig(artifact, "metadata", "licenses", force_default=[]),
        "cpes": artifact.get("cpes", []),
    }

    save_entry(findings, pkg_value, pkg_key)
