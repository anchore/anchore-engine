"""
Common utilities/lib for use by multiple services
"""

repository_subscription_types = ["repo_update"]

tag_subscription_types = ["policy_eval", "tag_update", "vuln_update", "analysis_update"]

subscription_types = repository_subscription_types + tag_subscription_types


resource_types = [
    "registries",
    "users",
    "images",
    "policies",
    "evaluations",
    "subscriptions",
    "archive",
]
bucket_types = [
    "analysis_data",
    "policy_bundles",
    "policy_evaluations",
    "query_data",
    "vulnerability_scan",
    "image_content_data",
    "manifest_data",
]
super_users = ["admin", "anchore-system"]
image_content_types = [
    "os",
    "files",
    "npm",
    "gem",
    "python",
    "java",
    "binary",
    "go",
    "malware",
]
image_metadata_types = ["manifest", "docker_history", "dockerfile"]
image_vulnerability_types = ["os", "non-os"]
os_package_types = ["rpm", "dpkg", "apkg", "kb"]
nonos_package_types = (
    "java",
    "python",
    "npm",
    "gem",
    "maven",
    "js",
    "composer",
    "nuget",
    "binary",
    "go",
)
