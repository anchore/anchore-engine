import os

from anchore_engine.analyzers.utils import dig


def save_entry(findings, engine_entry, pkg_key=None):
    if not pkg_key:
        pkg_name = engine_entry.get("name", "")
        pkg_version = engine_entry.get(
            "version", engine_entry.get("latest", "")
        )  # rethink this... ensure it's right
        pkg_key = engine_entry.get(
            "location",
            "/virtual/pypkg/site-packages/{}-{}".format(pkg_name, pkg_version),
        )

    findings["package_list"]["pkgs.python"]["base"][pkg_key] = engine_entry


def translate_and_save_entry(findings, artifact):
    """
    Handler function to map syft results for the python package type into the engine "raw" document format.
    """
    if "python-package-cataloger" not in artifact["foundBy"]:
        # engine only includes python findings for egg and wheel installations (with rich metadata)
        return

    site_pkg_root = artifact["metadata"]["sitePackagesRootPath"]
    name = artifact["name"]

    # anchore engine always uses the name, however, the name may not be a top-level package
    # instead default to the first top-level package unless the name is listed among the
    # top level packages explicitly defined in the metadata
    pkg_key_name = artifact["metadata"]["topLevelPackages"][0]
    if name in artifact["metadata"]["topLevelPackages"]:
        pkg_key_name = name

    pkg_key = os.path.join(site_pkg_root, pkg_key_name)
    origin = dig(artifact, "metadata", "author", force_default="")
    email = dig(artifact, "metadata", "authorEmail", default=None)
    if email:
        origin += " <%s>" % email

    files = []
    for file in dig(artifact, "metadata", "files", force_default=[]):
        files.append(os.path.join(site_pkg_root, file["path"]))

    # craft the artifact document
    pkg_value = {
        "name": name,
        "version": artifact["version"],
        "latest": artifact["version"],
        "files": files,
        "origin": origin,
        "license": dig(artifact, "metadata", "license", force_default=""),
        "location": site_pkg_root,
        "type": "python",
        "cpes": artifact.get("cpes", []),
    }

    # inject the artifact document into the "raw" analyzer document
    save_entry(findings, pkg_value, pkg_key)
