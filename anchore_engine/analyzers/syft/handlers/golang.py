from anchore_engine.analyzers.syft.handlers.common import save_entry_to_findings


def save_entry(findings, engine_entry, pkg_key=None):
    if not pkg_key:
        pkg_name = engine_entry.get("name", "")
        pkg_version = engine_entry.get("version", engine_entry.get("latest", ""))
        location = engine_entry.get("location", "/virtual/gopkg/")
        pkg_key = f"{location}:{pkg_name}@{pkg_version}"

    save_entry_to_findings(findings, engine_entry, "pkgs.go", pkg_key)


def translate_and_save_entry(findings, artifact):
    """
    Handler function to map syft results for the go-module type into the engine "raw" document format.
    """

    if len(artifact["locations"]) > 0:
        location = artifact["locations"][0]["path"]
    else:
        location = None

    # craft the artifact document
    pkg_value = {
        "name": artifact["name"],
        "version": artifact["version"],
        "location": location,
        "type": "go",
        "files": [],
        "license": "N/A",
        "origin": "N/A",
        "cpes": artifact.get("cpes", []),
        "metadata": artifact.get("metadata", {}),
    }

    # inject the artifact document into the "raw" analyzer document
    save_entry(findings, pkg_value)
